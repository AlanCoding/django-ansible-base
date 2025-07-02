import logging
from typing import Type

from django.apps import apps as global_apps
from django.db import DEFAULT_DB_ALIAS, models

from ansible_base.rbac import permission_registry
from ansible_base.rbac.remote import get_resource_prefix

logger = logging.getLogger(__name__)


def get_local_DAB_contenttypes(using: str, ct_model: Type[models.Model]) -> dict[tuple[str, str], models.Model]:
    # This should work in migration scenarios, but other code checks for existence of it on manager
    ct_model.objects.clear_cache()

    return {(ct.service, ct.model): ct for ct in ct_model.objects.using(using)}


def create_DAB_contenttypes(
    verbosity=2,
    using=DEFAULT_DB_ALIAS,
    apps=global_apps,
):
    """Create DABContentType for models in the given app.

    This is significantly different from the ContentType post-migrate method,
    because that creates types for all apps, and so this is only called one app at a time.
    DAB RBAC runs its post_migration logic just once, because the model list
    comes from the permission registry.
    """
    DABContentType = apps.get_model("dab_rbac", "DABContentType")
    ContentType = apps.get_model("contenttypes", "ContentType")

    content_types = get_local_DAB_contenttypes(using, DABContentType)

    # TODO: add api_slug field when added
    ct_data = []
    for model in permission_registry.all_registered_models:
        service = get_resource_prefix(model)
        if (service, model._meta.model_name) not in content_types:
            # The content type is not seen in existing entries, add to list for creation
            ct_item_data = dict(
                service=service,
                app_label=model._meta.app_label,
                model=model._meta.model_name,
            )
            # To make usage earier in a transitional period, we will set the content type
            # of any new entries created here to the id of its corresponding ContentType
            # from the actual contenttypes app, allowing many filters to work
            real_ct = ContentType.objects.get_for_model(model)
            if not DABContentType.objects.filter(id=real_ct.id).exists():
                ct_item_data['id'] = real_ct.id
            ct_data.append(ct_item_data)
    if not ct_data:
        return

    # To make usage earier in a transitional period, we will set the content type
    # of any new entries created here to the id of its corresponding ContentType
    # from the actual contenttypes app, allowing many filters to work
    cts = []
    for ct_item_data in ct_data:
        cts.append(DABContentType.objects.create(**ct_item_data))

    if verbosity >= 2:
        for ct in cts:
            logger.debug("Adding DAB content type " f"'{ct.service}:{ct.app_label} | {ct.model}'")

    for ct in DABContentType.objects.all():
        if not permission_registry.is_registered(ct.model_class()):
            logger.warning(f'{ct.model} is a stale content type in DAB RBAC')
            continue
        if parent_model := permission_registry.get_parent_model(ct.model_class()):
            parent_content_type = DABContentType.objects.get_for_model(parent_model)
            if ct.parent_content_type != parent_content_type:
                ct.parent_content_type = parent_content_type
                ct.save(update_fields=['parent_content_type'])
