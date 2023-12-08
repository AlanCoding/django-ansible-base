from django.db import transaction
from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied
from rest_framework.viewsets import ModelViewSet

from ansible_base.rbac.api.permissions import AuthenticatedReadAdminChange
from ansible_base.rbac.api.serializers import RoleDefinitionDetailSeraizler, RoleDefinitionSerializer, TeamAssignmentSerializer, UserAssignmentSerializer
from ansible_base.rbac.evaluations import has_super_permission
from ansible_base.rbac.models import RoleDefinition


class RoleDefinitionViewSet(ModelViewSet):
    """
    As per docs, RoleDefinition is interacted with like a normal model.
    """

    queryset = RoleDefinition.objects.all()
    serializer_class = RoleDefinitionSerializer
    permission_classes = [AuthenticatedReadAdminChange]

    def get_serializer_class(self):
        if self.action == 'update':
            return RoleDefinitionDetailSeraizler
        return super().get_serializer_class()


class BaseAssignmentViewSet(ModelViewSet):
    permission_classes = [permissions.IsAuthenticated]
    # PUT and PATCH are not allowed because these are immutable
    http_method_names = ['get', 'post', 'head', 'options', 'delete']

    def get_queryset(self):
        model = self.serializer_class.Meta.model
        if has_super_permission(self.request.user, 'view'):
            return model.objects.all()
        return model.visible_items(self.request.user)

    def perform_destroy(self, instance):
        if not self.request.user.has_obj_perm(instance, 'delete'):
            raise PermissionDenied

        rd = instance.object_role.role_definition
        obj = instance.object_role.content_object
        with transaction.atomic():
            rd.remove_permission(self.request.user, obj)


class TeamAssignmentViewSet(BaseAssignmentViewSet):
    serializer_class = TeamAssignmentSerializer


class UserAssignmentViewSet(BaseAssignmentViewSet):
    serializer_class = UserAssignmentSerializer
