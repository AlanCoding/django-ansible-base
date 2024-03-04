import re
from collections import defaultdict

from django.conf import settings
from rest_framework.exceptions import ValidationError

from ansible_base.lib.utils.models import is_add_perm
from ansible_base.rbac.permission_registry import permission_registry


def system_roles_enabled():
    return bool(settings.ANSIBLE_BASE_ALLOW_SINGLETON_USER_ROLES or settings.ANSIBLE_BASE_ALLOW_SINGLETON_TEAM_ROLES)


def validate_permissions_for_model(permissions, content_type) -> None:
    """Validation for creating a RoleDefinition

    This is called by the RoleDefinitionSerializer so clients will get these errors.
    It is also called by manager helper methods like RoleDefinition.objects.create_from_permissions
    which is done as an aid to tests and other apps integrating this library.
    """
    if content_type is None:
        if not system_roles_enabled():
            raise ValidationError('System-wide roles are not enabled')
        if permission_registry.team_permission in [perm.codename for perm in permissions]:
            raise ValidationError(f'The {permission_registry.team_permission} permission can not be used in global roles')

    # organize permissions by what model they should apply to
    # the "add" permission applies to the parent model of a permission
    # NOTE: issue for grandparent models https://github.com/ansible/django-ansible-base/issues/93
    permissions_by_model = defaultdict(list)
    for perm in permissions:
        cls = perm.content_type.model_class()
        if is_add_perm(perm.codename):
            role_model = permission_registry.get_parent_model(cls)
            if role_model is None and not system_roles_enabled():
                raise ValidationError(f'{perm.codename} permission requires system-wide roles, which are not enabled')
        else:
            role_model = cls
        if content_type and role_model._meta.model_name != content_type.model:
            # it is also valid to attach permissions to a role for the parent model
            child_model_names = [child_cls._meta.model_name for rel, child_cls in permission_registry.get_child_models(content_type.model_class())]
            if cls._meta.model_name not in child_model_names:
                raise ValidationError(f'{perm.codename} is not valid for content type {content_type.model}')
        permissions_by_model[role_model].append(perm)

    # check that all provided permissions are for registered models, or are system-wide
    unregistered_models = set(permissions_by_model.keys()) - set(permission_registry.all_registered_models) - set([None])
    if unregistered_models:
        display_models = ', '.join(str(cls._meta.verbose_name) for cls in unregistered_models)
        raise ValidationError(f'Permissions for unregistered models were given: {display_models}')

    # check that view permission is given for every model that has any permission listed
    for cls, model_permissions in permissions_by_model.items():
        for perm in model_permissions:
            if 'view' in perm.codename:
                break
            if cls is None and is_add_perm(perm.codename):
                # special case for system add permissions, because there is no associated parent object
                break
        else:
            display_perms = ', '.join([perm.codename for perm in model_permissions])
            raise ValidationError(f'Permissions for model {cls._meta.verbose_name} needs to include view, got: {display_perms}')


def codenames_for_cls(cls) -> list[str]:
    "Helper method that gives the Django permission codenames for a given class"
    return set([t[0] for t in cls._meta.permissions]) | set(f'{act}_{cls._meta.model_name}' for act in cls._meta.default_permissions)


def validate_codename_for_model(codename: str, model) -> str:
    """Shortcut method and validation to allow action name, codename, or app_name.codename

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


def validate_assignment_enabled(actor, content_type, has_team_perm=False):
    """Called in role assignment logic, inside RoleDefinition.give_permission

    Raises error if a setting disables the kind of permission being given.
    This mostly deals with team permissions.
    """
    team_team_allowed = settings.ANSIBLE_BASE_TEAM_TEAM_ALLOWED
    team_org_allowed = settings.ANSIBLE_BASE_TEAM_ORG_ALLOWED
    team_org_team_allowed = settings.ANSIBLE_BASE_TEAM_ORG_TEAM_ALLOWED

    if all([team_team_allowed, team_org_allowed, team_org_team_allowed]):
        return  # Everything is allowed
    team_model_name = permission_registry.team_model._meta.model_name
    if actor._meta.model_name != team_model_name:
        return  # Current prohibition settings only apply to team actors

    if not team_team_allowed and content_type.model == team_model_name:
        raise ValidationError('Assigning team permissions to other teams is not allowed')

    team_parent_model_name = permission_registry.get_parent_model(permission_registry.team_model)._meta.model_name
    if not team_org_allowed and content_type.model == team_parent_model_name:
        raise ValidationError(f'Assigning {team_parent_model_name} permissions to teams is not allowed')

    if not team_org_team_allowed and content_type.model == team_parent_model_name and has_team_perm:
        raise ValidationError(f'Assigning {team_parent_model_name} permissions to teams is not allowed')


def validate_assignment(rd, actor, obj) -> None:
    """General validation for making a role assignment

    This is called programatically in the give_permission and give_global_permission methods.
    Some of this covered by serializers as well by basic field validation and param gathering.
    """
    if actor._meta.model_name not in ('user', 'team'):
        raise ValidationError(f'Cannot give permission to {actor}, must be a user or team')

    obj_ct = permission_registry.content_type_model.objects.get_for_model(obj)
    if obj_ct.id != rd.content_type_id:
        rd_model = getattr(rd.content_type, "model", "global")
        raise ValidationError(f'Role type {rd_model} does not match object {obj_ct.model}')
