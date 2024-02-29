import re
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
            child_model_names = [child_cls._meta.model_name for rel, child_cls in permission_registry.get_child_models(content_type.model_class())]
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


def codenames_for_cls(cls) -> list[str]:
    return set([t[0] for t in cls._meta.permissions]) | set(f'{act}_{cls._meta.model_name}' for act in cls._meta.default_permissions)


def validate_codename_for_model(codename: str, model) -> str:
    """
    This institutes a shortcut for easier use of the evaluation methods
    so that user.has_obj_perm(obj, 'change') is the same as user.has_obj_perm(obj, 'change_inventory')
    assuming obj is an inventory.
    It also tries to protect the user by throwing an error if the permission does not work.
    """
    valid_codenames = codenames_for_cls(model)
    if (not codename.startswith('add')) and codename in valid_codenames:
        return codename
    if re.match(r'^[a-z]+$', codename):
        # convience to call JobTemplate.accessible_objects(u, 'execute')
        name = f'{codename}_{model._meta.model_name}'
    else:
        # sometimes permissions are referred to with the app name, like test_app.say_cow
        if '.' in codename:
            name = codename.split('.')[-1]
        else:
            name = codename
    if name in valid_codenames:
        if name.startswith('add'):
            raise RuntimeError(f'Add permissions only valid for parent models, received for {model._meta.model_name}')
        return name

    for rel, child_cls in permission_registry.get_child_models(model):
        if name in codenames_for_cls(child_cls):
            return name
    raise RuntimeError(f'The permission {name} is not valid for model {model._meta.model_name}')
