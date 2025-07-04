from rest_framework.viewsets import GenericViewSet, mixins

from ansible_base.lib.utils.views.django_app_api import AnsibleBaseDjangoAppApiView

from ..models import DABContentType, DABPermission, RoleTeamAssignment, RoleUserAssignment
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


# NOTE: role definitions are exchanged via the resources endpoint, so not included here


prefetch_related = ('created_by__resource', 'content_type', 'role_definition')


class ServiceRoleUserAssignmentViewSet(
    AnsibleBaseDjangoAppApiView,
    mixins.ListModelMixin,
    GenericViewSet,
):
    """List of assignments for cross-service communication"""

    queryset = RoleUserAssignment.objects.prefetch_related('user__resource', *prefetch_related)
    serializer_class = service_serializers.RoleUserAssignmentSerializer


class ServiceRoleTeamAssignmentViewSet(
    AnsibleBaseDjangoAppApiView,
    mixins.ListModelMixin,
    GenericViewSet,
):
    """List of team role assignments for cross-service communication"""

    queryset = RoleTeamAssignment.objects.prefetch_related('team__resource', *prefetch_related)
    serializer_class = service_serializers.RoleTeamAssignmentSerializer
