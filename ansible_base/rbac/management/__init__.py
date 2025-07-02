import logging

from django.apps import apps as global_apps
from django.db import DEFAULT_DB_ALIAS, router, connection

from ansible_base.rbac import permission_registry
from ansible_base.rbac.remote import get_resource_prefix

from .create_types import create_DAB_contenttypes

logger = logging.getLogger(__name__)


def create_dab_permissions(app_config, verbosity=2, interactive=True, using=DEFAULT_DB_ALIAS, apps=global_apps, **kwargs):
    """
    This is modified from the django auth.
    This will create DABPermission and DABContentType entries, only for registered models.

    The core logic is mainly in the other method, and this is to adhere to the post_migrate contract
    """
    if app_config.label != 'dab_rbac':
        return

    # NOTE: similar methods, like for contenttypes checks app models_module
    # but we know this is for dab_rbac, and we know it has models, so that is irrelevant

    if not permission_registry._registry:
        logger.warning('DAB RBAC app is installed but no models are registered')
        return

    try:
        DABContentType = apps.get_model("dab_rbac", "DABContentType")
    except LookupError:
        logger.debug('Skipping DAB RBAC type and permission creation since models are not available')
        return

    if not router.allow_migrate_model(using, DABContentType):
        # Uncommon case, code logic is using a replica database or something, unlikely to be relevant
        return

    sync_DAB_permissions(verbosity=verbosity, using=using, apps=global_apps)


def sync_DAB_permissions(verbosity=2, using=DEFAULT_DB_ALIAS, apps=global_apps):
    """Idepotent method to set database types and permissions for DAB RBAC

    This should make the database content reflect the model Meta data and
    registrations in the permission_registry for that app.
    """
    DABContentType = apps.get_model("dab_rbac", "DABContentType")
    Permission = apps.get_model("dab_rbac", "DABPermission")

    create_DAB_contenttypes(verbosity=verbosity, using=using, apps=apps)

    # This will hold the permissions we're looking for as (content_type, (codename, name))
    searched_perms = []
    # The codenames and ctypes that should exist.
    ctypes = set()
    for klass in permission_registry.all_registered_models:
        # Force looking up the content types in the current database
        # before creating foreign keys to them.
        service = get_resource_prefix(klass)
        ctype = DABContentType.objects.db_manager(using).get_for_model(klass, service=service, for_concrete_model=False)

        ctypes.add(ctype)

        for action in klass._meta.default_permissions:
            searched_perms.append(
                (
                    ctype,
                    (
                        f"{action}_{klass._meta.model_name}",
                        f"Can {action} {klass._meta.verbose_name_raw}",
                    ),
                )
            )
        for codename, name in klass._meta.permissions:
            searched_perms.append((ctype, (codename, name)))

    # Find all the Permissions that have a content_type for a model we're
    # looking for.  We don't need to check for codenames since we already have
    # a list of the ones we're going to create.
    all_perms = set(Permission.objects.using(using).filter(content_type__in=ctypes).values_list("content_type", "codename"))

    perms = []
    for ct, (codename, name) in searched_perms:
        if (ct.pk, codename) not in all_perms:
            permission = Permission()
            permission._state.db = using
            permission.codename = codename
            permission.name = name
            permission.content_type = ct
            permission.api_slug = f'{ct.service}.{codename}'
            perms.append(permission)

    Permission.objects.using(using).bulk_create(perms)
    for perm in perms:
        logger.debug("Adding permission '%s'" % perm)

    # Reset the sequence to avoid PK collision later
    if connection.vendor == 'postgresql':
        table = DABContentType._meta.db_table
        pk_column = DABContentType._meta.pk.column
        with connection.cursor() as cursor:
            cursor.execute(f"""
                SELECT setval(
                    pg_get_serial_sequence(%s, %s),
                    (SELECT MAX({pk_column}) FROM {table})
                )
            """, [table, pk_column])
