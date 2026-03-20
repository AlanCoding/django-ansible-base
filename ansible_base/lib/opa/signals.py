import logging

from django.conf import settings
from django.db.models.signals import m2m_changed, post_delete, post_save

logger = logging.getLogger(__name__)

SYNC_DEBOUNCE_SECONDS = 1.0


def ensure_user_opa_group(sender, instance, created, **kwargs):
    """Ensure a per-user OPAGroup exists for every new user."""
    if not created:
        return

    from ansible_base.lib.opa.models import OPAGroup

    group_name = f"user:{instance.pk}"
    group, was_created = OPAGroup.objects.get_or_create(
        name=group_name,
        defaults={"managed": True},
    )
    if was_created:
        group.users.add(instance)
        logger.info("Created per-user OPAGroup '%s' for user pk=%s", group_name, instance.pk)


def _trigger_sync(sender, **kwargs):
    """Signal handler that triggers a debounced OPA sync."""
    from ansible_base.lib.opa.rego.sync import sync_to_opa

    sync_to_opa(debounce_seconds=SYNC_DEBOUNCE_SECONDS)


def connect_user_signal():
    """Connect the post_save signal for auto per-user OPAGroup creation."""
    from django.apps import apps

    user_model = apps.get_model(settings.AUTH_USER_MODEL)
    post_save.connect(
        ensure_user_opa_group,
        sender=user_model,
        dispatch_uid="dab_opa_ensure_user_group",
    )


def connect_sync_signals():
    """Connect signals that trigger OPA sync on policy/role/assignment/membership changes."""
    from ansible_base.lib.opa.models import GroupRoleAssignment, OPAGroup, Policy, Role

    # Policy changes
    post_save.connect(_trigger_sync, sender=Policy, dispatch_uid="dab_opa_sync_policy_save")
    post_delete.connect(_trigger_sync, sender=Policy, dispatch_uid="dab_opa_sync_policy_delete")

    # Role changes
    post_save.connect(_trigger_sync, sender=Role, dispatch_uid="dab_opa_sync_role_save")
    post_delete.connect(_trigger_sync, sender=Role, dispatch_uid="dab_opa_sync_role_delete")

    # GroupRoleAssignment changes
    post_save.connect(_trigger_sync, sender=GroupRoleAssignment, dispatch_uid="dab_opa_sync_gra_save")
    post_delete.connect(_trigger_sync, sender=GroupRoleAssignment, dispatch_uid="dab_opa_sync_gra_delete")

    # OPAGroup.users M2M changes
    m2m_changed.connect(_trigger_sync, sender=OPAGroup.users.through, dispatch_uid="dab_opa_sync_group_users")
