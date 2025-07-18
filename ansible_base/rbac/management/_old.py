import logging

from django.apps import apps as global_apps
from django.contrib.contenttypes.management import create_contenttypes
from django.db import DEFAULT_DB_ALIAS, router

from ansible_base.rbac import permission_registry

logger = logging.getLogger(__name__)


def create_permissions_as_operation(apps, schema_editor):
    """This is a snapshot of the old logic to create permissions

    This is a matter of historical record and should not ever be changed.
    If an app calls the DAB RBAC method to create permissions in a migration,
    and that happened before the current custom content type model,
    this is where we intend to arrive.

    The logic should forevermore behave the same as it _used_ to.
    This avoids complicating the migration support matrix.
    Do not fix bugs in this method.

    As an inspirational quote
    > You gotta put your past, behind you
    """
    # NOTE: this is a snapshot version of the DAB RBAC permission creation logic
    # normally this runs post_migrate, but this exists to keep old logic
    for app_label in {'ansible', 'container', 'core', 'galaxy'}:
        app_config = global_apps.get_app_config(app_label)
        using = DEFAULT_DB_ALIAS

        # Ensure that contenttypes are created for this app. Needed if
        # 'ansible_base.rbac' is in INSTALLED_APPS before
        # 'django.contrib.contenttypes'.
        create_contenttypes(app_config, verbosity=2, interactive=True, using=using, apps=apps)

        try:
            app_config = apps.get_app_config(app_label)
            ContentType = apps.get_model("contenttypes", "ContentType")
            Permission = apps.get_model("dab_rbac", "DABPermission")
        except LookupError:
            return

        if not router.allow_migrate_model(using, Permission):
            return

        # This will hold the permissions we're looking for as (content_type, (codename, name))
        searched_perms = []
        # The codenames and ctypes that should exist.
        ctypes = set()
        for klass in app_config.get_models():
            if not permission_registry.is_registered(klass):
                continue
            # Force looking up the content types in the current database
            # before creating foreign keys to them.
            ctype = ContentType.objects.db_manager(using).get_for_model(klass, for_concrete_model=False)

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
                perms.append(permission)

        Permission.objects.using(using).bulk_create(perms)
        for perm in perms:
            logger.debug("Adding permission '%s'" % perm)

    logger.info('FINISHED CREATING PERMISSIONS')
