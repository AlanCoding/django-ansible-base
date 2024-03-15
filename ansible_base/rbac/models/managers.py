import logging

# Django
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db import models

# Django-rest-framework
from rest_framework.exceptions import ValidationError

# ansible_base RBAC logic imports
from ansible_base.lib.utils.models import is_add_perm
from ansible_base.rbac.permission_registry import permission_registry
from ansible_base.rbac.validators import validate_permissions_for_model
from ansible_base.rbac.models.permission import DABPermission
from ansible_base.rbac.models.evaluation import get_evaluation_model

logger = logging.getLogger('ansible_base.rbac.models')


class RoleDefinitionManager(models.Manager):
    def give_creator_permissions(self, user, obj):
        # If the user is a superuser, no need to bother giving the creator permissions
        for super_flag in settings.ANSIBLE_BASE_BYPASS_SUPERUSER_FLAGS:
            if getattr(user, super_flag):
                return True

        needed_actions = settings.ANSIBLE_BASE_CREATOR_DEFAULTS

        # User should get permissions to the object and any child objects under it
        model_and_children = set(cls for rel, cls in permission_registry.get_child_models(obj))
        model_and_children.add(type(obj))
        cts = ContentType.objects.get_for_models(*model_and_children).values()

        needed_perms = set()
        for perm in DABPermission.objects.filter(content_type__in=cts).prefetch_related('content_type'):
            action = perm.codename.split('_', 1)[0]
            if action in needed_actions:
                # do not save add permission on the object level, which does not make sense
                if is_add_perm(perm.codename) and perm.content_type.model == obj._meta.model_name:
                    continue
                needed_perms.add(perm.codename)

        has_permissions = set(get_evaluation_model(obj).get_permissions(user, obj))
        has_permissions.update(user.singleton_permissions())
        if set(needed_perms) - set(has_permissions):
            kwargs = {'permissions': needed_perms, 'name': f'{obj._meta.model_name}-creator-permission'}
            defaults = {'content_type': ContentType.objects.get_for_model(obj)}
            try:
                rd, _ = self.get_or_create(defaults=defaults, **kwargs)
            except ValidationError:
                logger.warning(f'Creating role definition {kwargs["name"]} as manged role because this is not allow as a custom role')
                defaults['managed'] = True
                rd, _ = self.get_or_create(defaults=defaults, **kwargs)

            rd.give_permission(user, obj)

    def get_or_create(self, permissions=(), defaults=None, **kwargs):
        "Add extra feature on top of existing get_or_create to use permissions list"
        if permissions:
            permissions = set(permissions)
            for existing_rd in self.prefetch_related('permissions'):
                existing_set = set(perm.codename for perm in existing_rd.permissions.all())
                if existing_set == permissions:
                    return (existing_rd, False)
            create_kwargs = kwargs.copy()
            if defaults:
                create_kwargs.update(defaults)
            return (self.create_from_permissions(permissions=permissions, **create_kwargs), True)
        return super().get_or_create(defaults=defaults, **kwargs)

    def create_from_permissions(self, permissions=(), **kwargs):
        "Create from a list of text-type permissions and do validation"
        perm_list = [permission_registry.permission_qs.get(codename=str_perm) for str_perm in permissions]

        ct = kwargs.get('content_type', None)
        if kwargs.get('content_type_id', None):
            ct = ContentType.objects.get(id=kwargs['content_type_id'])

        validate_permissions_for_model(perm_list, ct, managed=kwargs.get('managed', False))

        rd = self.create(**kwargs)
        rd.permissions.add(*perm_list)
        return rd
