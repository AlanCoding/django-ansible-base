from typing import Type

from django.apps import apps as global_apps
from django.db import DEFAULT_DB_ALIAS, models


def get_local_DAB_contenttypes(using: str, ct_model: Type[models.Model], service: str) -> dict[tuple[str, str], models.Model]:
    # This should work in migration scenarios, but other code checks for existence of it on manager
    ct_model.objects.clear_cache()

    return {
        (service, ct.model): ct
        for ct in ct_model.objects.using(using).filter(service=service)
    }


def create_DAB_contenttypes(
    rbac_models: list[Type[models.Model]],
    verbosity=2,
    using=DEFAULT_DB_ALIAS,
    apps=global_apps
):
    """Create DABContentType for models in the given app.

    This is significantly different from the ContentType post-migrate method,
    because that creates types for all apps, and so this is only called one app at a time.
    DAB RBAC runs its post_migration logic just once, because the model list
    comes from the permission registry.
    """
    DABContentType = apps.get_model("dab_rbac", "DABContentType")

    from ansible_base.rbac.remote import get_local_resource_prefix

    service = get_local_resource_prefix()

    content_types = get_local_DAB_contenttypes(
        using, DABContentType, service
    )
    if not rbac_models:
        return

    cts = [
        DABContentType(
            service=service,
            app_label=model._meta.app_label,
            model=model._meta.model_name,
        )
        for model in rbac_models
        if (service, model._meta.model_name) not in content_types
    ]
    if not cts:
        return
    DABContentType.objects.using(using).bulk_create(cts)
    if verbosity >= 2:
        for ct in cts:
            print(
                "Adding DAB content type "
                f"'{ct.service}:{ct.app_label} | {ct.model}'"
            )
