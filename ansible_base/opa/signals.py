import logging

from django.conf import settings
from django.db.models.signals import post_delete, post_save

logger = logging.getLogger(__name__)


def ensure_user_opa_group(sender, instance, created, **kwargs):
    """Ensure a per-user OPAGroup exists for every new user."""
    if not created:
        return

    from ansible_base.opa.models import OPAGroup

    group_name = f"user:{instance.pk}"
    group, was_created = OPAGroup.objects.get_or_create(
        name=group_name,
        defaults={"managed": True},
    )
    if was_created:
        group.users.add(instance)
        logger.info("Created per-user OPAGroup '%s' for user pk=%s", group_name, instance.pk)


def _trigger_policy_sync(sender, **kwargs):
    """Signal handler that syncs policy definitions to OPA when policies change."""
    from ansible_base.opa.rego.sync import sync_policies_to_opa

    sync_policies_to_opa()


def connect_user_signal():
    """Connect the post_save signal for auto per-user OPAGroup creation."""
    from django.apps import apps

    user_model = apps.get_model(settings.AUTH_USER_MODEL)
    post_save.connect(
        ensure_user_opa_group,
        sender=user_model,
        dispatch_uid="dab_opa_ensure_user_group",
    )


def connect_policy_sync_signals():
    """Connect signals that sync policy definitions to OPA when policies change."""
    from ansible_base.opa.models import Policy

    post_save.connect(_trigger_policy_sync, sender=Policy, dispatch_uid="dab_opa_sync_policy_save")
    post_delete.connect(_trigger_policy_sync, sender=Policy, dispatch_uid="dab_opa_sync_policy_delete")
