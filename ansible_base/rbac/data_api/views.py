from collections import OrderedDict
from typing import Type

from django.db.models import Model, Exists, OuterRef, Q
from django.contrib.contenttypes.models import ContentType
from rest_framework.reverse import reverse

from rest_framework import permissions
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import viewsets
from rest_framework import mixins
from rest_framework.permissions import IsAuthenticated

from ansible_base.lib.utils.views.django_app_api import AnsibleBaseDjangoAppApiView
from ansible_base.rbac.data_api import serializers
from ansible_base.rbac.permission_registry import permission_registry
from ansible_base.rbac.models import RoleUserAssignment, RoleTeamAssignment
from ansible_base.rbac.validators import permissions_allowed_for_role, system_roles_enabled
from ansible_base.rbac.evaluations import get_evaluation_model
from ansible_base.rbac.policies import visible_users


class RoleDataIndexView(AnsibleBaseDjangoAppApiView, GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, format=None):
        data = OrderedDict()
        data['types'] = reverse('rbactype-list')
        data['allowed_permissions'] = reverse('role-allowed-permissions')
        data['users'] = reverse('rbacuser-list')

        return Response(data)


def list_combine_values(data: dict[Type[Model], list[str]]) -> list[str]:
    "Utility method to merge everything in .values() into a single list"
    ret = []
    for this_list in data.values():
        ret += this_list
    return ret


class RoleMetadataView(AnsibleBaseDjangoAppApiView, GenericAPIView):
    """General data about models and permissions tracked by django-ansible-base RBAC

    Information from this endpoint should be static given a server version.
    This reflects model definitions, registrations with the permission registry,
    and enablement of RBAC features in settings.

    allowed_permissions: Valid permissions for a role of a given content_type
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.RoleMetadataSerializer

    def get(self, request, format=None):
        data = OrderedDict()
        allowed_permissions = OrderedDict()

        all_models = sorted(permission_registry.all_registered_models, key=lambda cls: cls._meta.model_name)

        role_model_types = list(all_models)
        if system_roles_enabled():
            role_model_types += [None]
        for cls in role_model_types:
            if cls is None:
                cls_repr = 'system'
            else:
                cls_repr = f"{permission_registry.get_resource_prefix(cls)}.{cls._meta.model_name}"
            allowed_permissions[cls_repr] = []
            for codename in list_combine_values(permissions_allowed_for_role(cls)):
                perm = permission_registry.permission_qs.get(codename=codename)
                ct = permission_registry.content_type_model.objects.get_for_id(perm.content_type_id)
                perm_repr = f"{permission_registry.get_resource_prefix(ct.model_class())}.{codename}"
                allowed_permissions[cls_repr].append(perm_repr)

        data['allowed_permissions'] = allowed_permissions

        serializer = self.get_serializer(data)

        return Response(serializer.data)


class AbstractReadOnlyViewSet(AnsibleBaseDjangoAppApiView, mixins.RetrieveModelMixin, mixins.ListModelMixin, viewsets.GenericViewSet):
    pass


class ModelTypeMixin:
    def _get_model_cls(self):
        model_name = self.kwargs['model_name']
        ct = ContentType.objects.get(model=model_name)
        model_cls = ct.model_class()
        return model_cls

    def _object_codenames(self, model_cls):
        return permissions_allowed_for_role(model_cls)[model_cls]

    def get_serializer_context(self):
        context = super().get_serializer_context()
        # conditional only for detail view
        if 'model_name' in self.kwargs:
            context['model'] = self._get_model_cls()
            context['object_codenames'] = self._object_codenames(context['model'])
        return context


class TypeViewSet(ModelTypeMixin, AbstractReadOnlyViewSet):
    lookup_url_kwarg = 'model_name'
    lookup_field = 'model'

    serializer_class = serializers.ContentTypeSerializer
    permission_classes = [IsAuthenticated,]

    def get_queryset(self):
        return permission_registry.content_type_model.objects.filter(
            model__in=[cls._meta.model_name for cls in permission_registry.all_registered_models]
        )


class ObjectViewSet(ModelTypeMixin, AbstractReadOnlyViewSet):
    lookup_url_kwarg = 'object_id'

    def get_serializer_class(self):
        model_cls = self._get_model_cls()

        class OneModelSerializer(serializers.GenericObjectSerializer):
            class Meta:
                model = model_cls
                fields = serializers.GenericObjectSerializer.Meta.fields

        return OneModelSerializer

    def get_queryset(self):
        model_cls = self._get_model_cls()
        qs = model_cls.objects
        ct = ContentType.objects.get_for_model(model_cls)
        evaluation_cls = get_evaluation_model(model_cls)
        u = self.request.user

        # Annotate user permissions, analog to AWX user_capabilities
        for codename in self._object_codenames(model_cls):
            evaluation_qs = evaluation_cls.objects.filter(
                content_type_id=ct.id, object_id=OuterRef('id'), role__users=u, codename=codename
            )
            qs = qs.annotate(**{f'can_{codename}': Exists(evaluation_qs)})

        return qs.prefetch_related('object_roles__users', 'object_roles__teams', 'object_roles__role_definition')


class RoleUserAssignmentViewSet(ModelTypeMixin, AbstractReadOnlyViewSet):
    serializer_class = serializers.UserAssignmentSerializer
    permission_classes = [IsAuthenticated,]

    def _get_obj(self):
        if not hasattr(self, '_saved_obj'):
            model_cls = self._get_model_cls()
            self._saved_obj = model_cls.objects.get(pk=self.kwargs['object_id'])
        return self._saved_obj

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['object'] = self._get_obj()
        return context

    def get_queryset(self):
        obj = self._get_obj()
        ct = ContentType.objects.get_for_model(obj)
        codenames = self._object_codenames(type(obj))
        object_role_Q = Q(object_id=obj.pk, content_type=ct)
        working_obj = obj
        while True:
            parent_field_name = permission_registry.get_parent_fd_name(working_obj)
            if not parent_field_name:
                break
            parent_model = permission_registry.get_parent_model(working_obj)
            parent_ct = ContentType.objects.get_for_model(parent_model)
            parent_obj = getattr(working_obj, parent_field_name)
            working_obj = parent_obj
            object_role_Q |= Q(content_type=parent_ct, object_id=parent_obj.pk, role_definition__permissions__codename__in=codenames)

        return RoleUserAssignment.objects.filter(
            object_role_Q | Q(content_type=None, role_definition__permissions__codename__in=codenames)
        ).distinct()


class UserInfoViewSet(AbstractReadOnlyViewSet):
    serializer_class = serializers.UserInfoSerializer
    permission_classes = [IsAuthenticated,]

    def get_queryset(self):
        qs = visible_users(self.request.user)
        return qs

# Plan
# object list (object role based list)
#  - object access list (user-based sublist)
# user list
# team list

