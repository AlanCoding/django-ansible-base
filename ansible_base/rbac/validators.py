from collections import defaultdict

from django.conf import settings
from rest_framework.exceptions import ValidationError

from ansible_base.lib.utils.models import is_add_perm
from ansible_base.rbac.permission_registry import permission_registry


def system_roles_enabled():
    return bool(settings.ANSIBLE_BASE_ALLOW_SINGLETON_USER_ROLES or settings.ANSIBLE_BASE_ALLOW_SINGLETON_TEAM_ROLES)


def validate_permissions_for_model(permissions, content_type):
    if content_type is None:
        if not system_roles_enabled():
            raise ValidationError('System-wide roles are not enabled')
        if permission_registry.team_permission in permissions:
            raise ValidationError(f'The {permission_registry.team_permission} permission can not be used in global roles')

    # organize permissions by what model they should apply to
    # the "add" permission applies to the parent model of a permission
    # NOTE: issue for grandparent models https://github.com/ansible/django-ansible-base/issues/93
    permissions_by_model = defaultdict(list)
    for perm in permissions:
        cls = perm.content_type.model_class()
        if is_add_perm(perm.codename):
            to_model = permission_registry.get_parent_model(cls)
            if to_model is None and not system_roles_enabled():
                raise ValidationError(f'{perm.codename} permission requires system-wide roles, which are not enabled')
        else:
            to_model = cls
        if content_type and to_model._meta.model_name != content_type.model:
            # it is also valid to attach permissions to a role for the parent model
            child_model_names = [child_cls._meta.model_name for rel, child_cls in permission_registry.get_child_models(content_type.model)]
            if cls._meta.model_name not in child_model_names:
                raise ValidationError(f'{perm.codename} is not valid for content type {content_type.model}')
        permissions_by_model[to_model].append(perm)

    # check that all provided permissions are for registered models
    unregistered_models = set(permissions_by_model.keys()) - set(permission_registry.all_registered_models)
    if unregistered_models:
        display_models = ', '.join(str(cls._meta.verbose_name) for cls in unregistered_models)
        raise ValidationError(f'Permissions for unregistered models were given: {display_models}')

    # check that view permission is given for every model that has any permission listed
    for cls, model_permissions in permissions_by_model.items():
        for perm in model_permissions:
            if 'view' in perm.codename:
                break
        else:
            display_perms = ', '.join([perm.codename for perm in model_permissions])
            raise ValidationError(f'Permissions for model {cls._meta.verbose_name} needs to include view, got: {display_perms}')
