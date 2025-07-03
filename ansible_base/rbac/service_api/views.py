from rest_framework.viewsets import GenericViewSet, mixins

from ansible_base.lib.utils.views.django_app_api import AnsibleBaseDjangoAppApiView

from ..models import DABContentType, DABPermission
from . import serializers as service_serializers


class RoleContentTypeViewSet(
    AnsibleBaseDjangoAppApiView,
    mixins.ListModelMixin,
    GenericViewSet,
):
    """List of types registered with the RBAC system, or loaded in from external system"""

    queryset = DABContentType.objects.prefetch_related('parent_content_type').all()
    serializer_class = service_serializers.DABContentTypeSerializer


class RolePermissionTypeViewSet(
    AnsibleBaseDjangoAppApiView,
    mixins.ListModelMixin,
    GenericViewSet,
):
    """List of permissions managed with the RBAC system"""

    queryset = DABPermission.objects.prefetch_related('content_type').all()
    serializer_class = service_serializers.DABPermissionSerializer
