import logging

from django.conf import settings
from django.db.models.signals import post_save

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


def connect_user_signal():
    """Connect the post_save signal for auto per-user OPAGroup creation."""
    from django.apps import apps

    user_model = apps.get_model(settings.AUTH_USER_MODEL)
    post_save.connect(
        ensure_user_opa_group,
        sender=user_model,
        dispatch_uid="dab_opa_ensure_user_group",
    )
