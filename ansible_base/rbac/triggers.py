import logging
import os
import sys

from django.apps import apps
from django.conf import settings
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db.models.signals import m2m_changed, post_delete, post_init, post_save
from django.db.utils import ProgrammingError

from ansible_base.migrations._managed_definitions import setup_managed_role_definitions
from ansible_base.models.rbac import ObjectRole, RoleDefinition, RoleEvaluation
from ansible_base.rbac.caching import compute_object_role_permissions, compute_team_member_roles
from ansible_base.rbac.permission_registry import permission_registry

logger = logging.getLogger('ansible_base.rbac.triggers')


'''
As the caching module will fill in cached data,
this module shall manage the calling of the caching methods.
Sounds simple, but is actually more complicated that the caching logic itself.
'''


def needed_updates_on_assignment(role_definition, actor, object_role, created=False, giving=True):
    """
    If a user or a team is granted a role or has a role revoked,
    then this returns instructions for what needs to be updated
    returns tuple
        (bool: should update team owners, set: object roles to update)
    """
    # we maintain a list of object roles that we need to update evaluations for
    to_update = set()
    if created:
        to_update.add(object_role)

    has_team = object_role.role_definition.permissions.filter(codename=permission_registry.team_permission).exists()
    changes_team_owners = False

    # If permissions for team are changed. That tends to affect a lot.
    if actor._meta.model_name != 'user':
        to_update.update(
            set(
                ObjectRole.objects.filter(
                    permission_partials__in=RoleEvaluation.objects.filter(
                        codename=permission_registry.team_permission, object_id=actor.id, content_type_id=ContentType.objects.get_for_model(actor).id
                    )
                )
            )
        )
        if not giving:
            # this will delete some permission assignments that will be removed from this relationship
            to_update.update(object_role.descendent_roles())
        changes_team_owners = True

    deleted = False
    if (not giving) and (not (object_role.users.exists() or object_role.teams.exists())):
        # time to delete the object role because it is unused
        if object_role in to_update:
            to_update.remove(object_role)
        deleted = True

    # giving or revoking team permissions may not change the parentage
    # but this will still change what downstream roles grant what permissions
    if (has_team and created) or (giving and changes_team_owners):
        to_update.update(object_role.descendent_roles())

    # actions which can change the team parentage structure
    recompute_teams = bool(has_team and (created or deleted or changes_team_owners))

    return (recompute_teams, to_update)


def update_after_assignment(update_teams, to_update):
    "Call this with the output of needed_updates_on_assignment"
    if update_teams:
        compute_team_member_roles()

    compute_object_role_permissions(object_roles=to_update)


def permissions_changed(instance, action, model, pk_set, reverse, **kwargs):
    if action.startswith('pre_'):
        return
    to_recompute = set(ObjectRole.objects.filter(role_definition=instance))
    if not to_recompute:
        return
    logger.info(f'{instance} permissions {action}, pks={pk_set}')
    if reverse:
        raise RuntimeError('Removal of permssions through reverse relationship not supported')
    if action in ('post_add', 'post_remove'):
        if Permission.objects.filter(codename=permission_registry.team_permission, pk__in=pk_set).exists():
            for object_role in to_recompute.copy():
                to_recompute.update(object_role.descendent_roles())
            compute_team_member_roles()
        compute_object_role_permissions(object_roles=to_recompute)
    elif action == 'post_clear':
        # unfortunately this does not give us a list of permissions to work with
        # this is slow, not ideal, but will at least be correct
        compute_team_member_roles()
        compute_object_role_permissions()


m2m_changed.connect(permissions_changed, sender=RoleDefinition.permissions.through)


def set_original_parent(sender, instance, **kwargs):
    '''
    connect to post_init signal
    Used to set the original, or
    pre-save parent id (usually organization), so we can later determine if
    the organization field has changed.
    '''
    parent_field_name = permission_registry.get_parent_fd_name(instance)
    if parent_field_name is None:
        return
    instance.__rbac_original_parent_id = getattr(instance, f'{parent_field_name}_id')


def post_save_update_obj_permissions(instance):
    "Utility method shared by multiple signals"
    to_update = set()
    parent_ct = ContentType.objects.get_for_model(permission_registry.get_parent_model(instance))
    parent_field_name = permission_registry.get_parent_fd_name(instance)

    # Account for organization roles, new and old
    new_parent_id = getattr(instance, f'{parent_field_name}_id')
    if new_parent_id:
        to_update.update(set(ObjectRole.objects.filter(content_type=parent_ct, object_id=new_parent_id)))
    if hasattr(instance, '__rbac_original_parent_id') and instance.__rbac_original_parent_id:
        to_update.update(set(ObjectRole.objects.filter(content_type=parent_ct, object_id=instance.__rbac_original_parent_id)))

    # Account for parent team roles of those organization roles
    ancestors = set(ObjectRole.objects.filter(provides_teams__has_roles__in=to_update))
    to_update.update(ancestors)

    # If the actual object changed (created or modified) was a team, any org role
    # that has member_team needs to be updated, and any parent teams that have that role
    team_type = apps.get_model(settings.ROLE_TEAM_MODEL)
    if instance._meta.model_name == team_type._meta.model_name:
        compute_team_member_roles()

    if to_update:
        compute_object_role_permissions(object_roles=to_update)


def recompute_object_role_permissions(instance, created, *args, **kwargs):
    """
    Connect to post_save signal for objects in the permission registry
    If the parent object changes, this rebuilds the cache
    """
    # Exit right away if object does not have any parent objects
    parent_field_name = permission_registry.get_parent_fd_name(instance)
    if parent_field_name is None:
        return

    # If child object is created and parent object has existing ObjectRoles
    # evaluations for the parent object roles need to be added
    if created:
        post_save_update_obj_permissions(instance)
        return

    # The parent object can not have changed if update_fields was given and did not list that field
    update_fields = kwargs.get('update_fields', None)
    if update_fields and not (parent_field_name in update_fields or f'{parent_field_name}_id' in update_fields):
        return

    # Handle the unusual situation where the parent object changes
    current_parent_id = getattr(instance, f'{parent_field_name}_id')
    if hasattr(instance, '__rbac_original_parent_id') and instance.__rbac_original_parent_id != current_parent_id:
        logger.info(f'Object {instance} changed RBAC parent {instance.__rbac_original_parent_id}-->{current_parent_id}')
        post_save_update_obj_permissions(instance)


def remove_object_roles(instance, *args, **kwargs):
    """
    Call this when deleting an object to cascade delete its object roles
    Deleting a team can have consequences for the rest of the graph
    """
    indirectly_affected_roles = set()
    team_type = apps.get_model(settings.ROLE_TEAM_MODEL)
    if instance._meta.model_name == team_type._meta.model_name:
        for team_role in instance.member_roles.all():
            indirectly_affected_roles.update(team_role.descendent_roles())
        compute_team_member_roles()
        compute_object_role_permissions(object_roles=indirectly_affected_roles)

    ct = ContentType.objects.get_for_model(type(instance))
    ObjectRole.objects.filter(content_type=ct, object_id=instance.id).delete()


def post_migration_rbac_setup(*args, **kwargs):
    """
    Return if running django or py.test unit tests.
    Logic is taken from AWX is_testing, it could be cut down on
    """
    if 'PYTEST_CURRENT_TEST' in os.environ.keys():
        return
    if len(sys.argv) >= 1 and ('py.test' in sys.argv[0] or 'py/test.py' in sys.argv[0]):
        return
    elif len(sys.argv) >= 2 and sys.argv[1] == 'test':
        return

    try:
        RoleDefinition.objects.first()
    except ProgrammingError:
        return  # this happens when migrating backwards, tables do not exist at prior states

    setup_managed_role_definitions(apps, None)
    compute_team_member_roles()
    compute_object_role_permissions()


def connect_rbac_signals(cls):
    post_save.connect(recompute_object_role_permissions, sender=cls, dispatch_uid='permission-registry-post-save')
    post_delete.connect(remove_object_roles, sender=cls, dispatch_uid='permission-registry-post-delete')
    post_init.connect(set_original_parent, sender=cls, dispatch_uid='permission-registry-save-prior-parent')
