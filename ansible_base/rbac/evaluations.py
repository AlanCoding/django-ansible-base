import re

from django.conf import settings

from ansible_base.rbac import permission_registry
from ansible_base.rbac.models import ObjectRole, RoleDefinition, get_evaluation_model

"""
RoleEvaluation or RoleEvaluationUUID models are the authority for permission evaluations,
meaning, determining whether a user has a permission to an object.

Methods needed for producing querysets (of objects a user has a permission to
or users that have a permission to an object) or making single evaluations
are defined on the RoleEvaluation model.

This module has logic to attach those evaluation methods to the external
models in an app using these RBAC internals.
"""


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


class BaseEvaluationDescriptor:
    """
    Descriptors have to be used to attach what are effectively a @classmethod
    to an external model, like MyModel.accessible_objects(u, 'view_mymodel')
    because this how we obtain a reference to MyModel
    """

    def __init__(self, cls):
        self.cls = cls


def has_super_permission(user, codename='change') -> bool:
    if user._meta.model_name != permission_registry.user_model._meta.model_name:
        if user._meta.model_name == permission_registry.team_model._meta.model_name:
            return False  # Super permission flags only exist for users, teams can use global roles
        else:
            raise RuntimeError(f'Evaluation methods are for users or teams, got {user._meta.model_name}: {user}')
    for super_flag in settings.ANSIBLE_BASE_BYPASS_SUPERUSER_FLAGS:
        if getattr(user, super_flag):
            return True
    for action, super_flag in settings.ANSIBLE_BASE_BYPASS_ACTION_FLAGS.items():
        if codename.startswith(action) and getattr(user, super_flag):
            return True
    return False


class AccessibleObjectsDescriptor(BaseEvaluationDescriptor):
    def __call__(self, user, codename='view', **kwargs):
        full_codename = validate_codename_for_model(codename, self.cls)
        if has_super_permission(user, codename) or (full_codename in user.singleton_permissions()):
            return self.cls.objects.all()
        return get_evaluation_model(self.cls).accessible_objects(self.cls, user, full_codename, **kwargs)


class AccessibleIdsDescriptor(BaseEvaluationDescriptor):
    def __call__(self, user, codename, **kwargs):
        full_codename = validate_codename_for_model(codename, self.cls)
        if has_super_permission(user, codename):
            return self.cls.objects.values_list('id', flat=True)
        return get_evaluation_model(self.cls).accessible_ids(self.cls, user, full_codename, **kwargs)


def bound_has_obj_perm(self, obj, codename) -> bool:
    full_codename = validate_codename_for_model(codename, obj)
    if has_super_permission(self, codename) or (full_codename in self.singleton_permissions()):
        return True
    return get_evaluation_model(obj).has_obj_perm(self, obj, full_codename)


def bound_singleton_permissions(self) -> set[str]:
    if hasattr(self, '_singleton_permissions'):
        return self._singleton_permissions
    perm_set = set()
    if settings.ANSIBLE_BASE_ALLOW_SINGLETON_USER_ROLES:
        rd_qs = RoleDefinition.objects.filter(user_assignments__user=self, content_type=None)
        perm_qs = permission_registry.permission_model.objects.filter(role_definitions__in=rd_qs)
        perm_set.update(perm_qs.values_list('codename', flat=True))
    if settings.ANSIBLE_BASE_ALLOW_SINGLETON_TEAM_ROLES:
        user_teams_qs = permission_registry.team_model.objects.filter(member_roles__in=ObjectRole.objects.filter(users=self))
        rd_qs = RoleDefinition.objects.filter(team_assignments__team__in=user_teams_qs, content_type=None)
        perm_qs = permission_registry.permission_model.objects.filter(role_definitions__in=rd_qs)
        perm_set.update(perm_qs.values_list('codename', flat=True))
    return perm_set


def connect_rbac_methods(cls):
    cls.add_to_class('access_qs', AccessibleObjectsDescriptor(cls))
    cls.add_to_class('access_ids_qs', AccessibleIdsDescriptor(cls))
