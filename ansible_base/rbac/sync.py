"""
Module is a parallel to resource_registry

ansible_base.resource_registry.utils.sync_to_resource_server.sync_to_resource_server

This module handles RBAC-specific reverse-sync scenarios:
1. Role assignments - which have key differences:
   - totally immutable model
   - have very weird way of referencing related objects
   - must run various internal RBAC logic for rebuilding RoleEvaluation entries

2. RoleDefinition sync timing - which has timing issues:
   - post_save fires before many-to-many relations are saved
   - permissions need to be attached before syncing
"""

import logging
from contextlib import contextmanager

logger = logging.getLogger('ansible_base.rbac.sync')


def reverse_sync_enabled_all_conditions(assignment):
    """This checks for basically all cases we do not reverse sync
    1. object level flag for skipping the sync
    2. environment variable to skip sync
    3. context manager to disable sync
    4. RESOURCE_SERVER setting not actually set
    """
    from ansible_base.resource_registry.apps import _should_reverse_sync
    from ansible_base.resource_registry.signals.handlers import reverse_sync_enabled
    from ansible_base.resource_registry.utils.sync_to_resource_server import should_skip_reverse_sync

    if not _should_reverse_sync():
        return False

    if not reverse_sync_enabled.enabled:
        return False

    if should_skip_reverse_sync(assignment):
        return

    return True


def maybe_reverse_sync_assignment(assignment):
    if not reverse_sync_enabled_all_conditions(assignment):
        return

    from ansible_base.resource_registry.utils.sync_to_resource_server import get_current_user_resource_client

    client = get_current_user_resource_client()
    client.sync_assignment(assignment)


def maybe_reverse_sync_unassignment(role_definition, actor, content_object):
    if not reverse_sync_enabled_all_conditions(role_definition):
        return

    from ansible_base.resource_registry.utils.sync_to_resource_server import get_current_user_resource_client

    client = get_current_user_resource_client()
    client.sync_unassignment(role_definition, actor, content_object)


def _should_reverse_sync(instance) -> bool:
    """Check if reverse sync should be performed for the given instance.

    This checks the same conditions as the signal handler but without
    relying on the global reverse_sync_enabled state being temporarily disabled.
    """
    from ansible_base.resource_registry.apps import _should_reverse_sync as _global_should_sync
    from ansible_base.resource_registry.utils.sync_to_resource_server import should_skip_reverse_sync

    # Check global RESOURCE_SERVER configuration
    if not _global_should_sync():
        return False

    # Check instance-specific skip conditions
    if should_skip_reverse_sync(instance):
        return False

    return True


class DelayedReverseSyncContext:
    """Context class for delayed reverse sync operations."""

    def __init__(self, action="update"):
        self.action = action
        self.instance = None

    def set_instance(self, instance):
        """Set the instance to sync after the context exits."""
        self.instance = instance


@contextmanager
def delayed_reverse_sync(instance, action="update"):
    """Context manager that disables reverse-sync during execution, then manually syncs afterward.

    This is useful for operations where the instance needs to be fully constructed
    (including many-to-many relationships) before syncing to the resource server.

    This solves the timing issue where post_save fires before many-to-many
    relations are saved, causing empty permissions to be synced.

    Args:
        instance: The Django model instance to sync (can be None for create operations)
        action: The action type ("create" or "update")

    Usage:
        # For updates
        with delayed_reverse_sync(role_def, "update"):
            # Perform operations that modify the instance
            role_def.permissions.set(permissions)
        # Sync happens here if appropriate

        # For creates
        ctx = delayed_reverse_sync(None, "create")
        with ctx:
            instance = serializer.save()
            ctx.set_instance(instance)
        # Sync happens here if appropriate
    """
    from ansible_base.resource_registry.signals.handlers import no_reverse_sync, sync_to_resource_server_post_save

    # Create a context object that can be updated
    context = DelayedReverseSyncContext(action)
    context.instance = instance

    with no_reverse_sync():
        yield context

    # After the context, check if we should sync and do it manually
    final_instance = context.instance
    if final_instance and _should_reverse_sync(final_instance):
        logger.debug(f"Performing delayed reverse-sync for {final_instance} (action: {action})")
        # Use the same logic as the post_save signal handler
        created = (action == "create")
        sync_to_resource_server_post_save(
            sender=type(final_instance),
            instance=final_instance,
            created=created,
            update_fields=None
        )
    else:
        logger.debug(f"Skipping delayed reverse-sync for {final_instance} (action: {action})")
