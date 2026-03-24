import logging

from django.contrib.auth import get_user_model
from rest_framework import permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from ansible_base.lib.utils.views.django_app_api import AnsibleBaseDjangoAppApiView
from ansible_base.lib.utils.views.permissions import try_add_oauth2_scope_permission
from ansible_base.opa.api.serializers import (
    GroupRoleAssignmentSerializer,
    OPAGroupMembershipSerializer,
    OPAGroupSerializer,
    PolicySerializer,
    RoleDetailSerializer,
    RoleSerializer,
    UserEffectiveScopeSerializer,
)
from ansible_base.opa.evaluator import local_get_scope
from ansible_base.opa.models import GroupRoleAssignment, OPAGroup, Policy, Role
from ansible_base.opa.registry import opa_registry

logger = logging.getLogger(__name__)


class IsSuperuser(permissions.BasePermission):
    """Temporary permission class: only superusers can manage OPA resources.

    TODO: Replace with OPA-based self-management once the bootstrapping
    design is finalized. See DEVELOPMENT_PLAN.md Phase 7 notes.
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.method in permissions.SAFE_METHODS:
            return True
        return request.user.is_superuser

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return request.user.is_superuser


class RoleViewSet(AnsibleBaseDjangoAppApiView, ModelViewSet):
    """Manage OPA roles.

    Roles contain policies that define what resources and actions are granted.
    System-managed roles cannot be renamed or deleted.
    """

    queryset = Role.objects.prefetch_related("policies").all()
    serializer_class = RoleSerializer
    permission_classes = try_add_oauth2_scope_permission([IsSuperuser])

    def get_serializer_class(self):
        if self.action in ("update", "partial_update"):
            return RoleDetailSerializer
        return RoleSerializer

    def perform_destroy(self, instance):
        if instance.managed:
            return Response(
                {"detail": "Cannot delete a managed role."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        super().perform_destroy(instance)


class PolicyViewSet(AnsibleBaseDjangoAppApiView, ModelViewSet):
    """Manage OPA policies.

    Policies define access rules: a resource, action, field, operator,
    and value that together form a queryset filter clause.
    Policies are validated against the OPA registry on create/update.
    """

    queryset = Policy.objects.select_related("role").all()
    serializer_class = PolicySerializer
    permission_classes = try_add_oauth2_scope_permission([IsSuperuser])
    filterset_fields = ["role", "resource", "action"]


class OPAGroupViewSet(AnsibleBaseDjangoAppApiView, ModelViewSet):
    """Manage OPA groups.

    Groups contain users and can have roles assigned to them.
    System-managed groups (e.g. per-user groups) cannot be deleted.
    """

    queryset = OPAGroup.objects.prefetch_related("users").all()
    serializer_class = OPAGroupSerializer
    permission_classes = try_add_oauth2_scope_permission([IsSuperuser])

    def perform_destroy(self, instance):
        if instance.managed:
            return Response(
                {"detail": "Cannot delete a managed group."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        super().perform_destroy(instance)

    @action(detail=True, methods=["post"], url_path="add_user")
    def add_user(self, request, pk=None):
        """Add a user to this group."""
        group = self.get_object()
        serializer = OPAGroupMembershipSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        User = get_user_model()
        try:
            user = User.objects.get(pk=serializer.validated_data["user_id"])
        except User.DoesNotExist:
            return Response(
                {"detail": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        group.users.add(user)

        return Response({"detail": f"User {user.pk} added to group {group.name}."})

    @action(detail=True, methods=["post"], url_path="remove_user")
    def remove_user(self, request, pk=None):
        """Remove a user from this group."""
        group = self.get_object()
        serializer = OPAGroupMembershipSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        User = get_user_model()
        try:
            user = User.objects.get(pk=serializer.validated_data["user_id"])
        except User.DoesNotExist:
            return Response(
                {"detail": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        group.users.remove(user)

        return Response({"detail": f"User {user.pk} removed from group {group.name}."})


class GroupRoleAssignmentViewSet(AnsibleBaseDjangoAppApiView, ModelViewSet):
    """Manage group-to-role assignments.

    Assigning a role to a group grants all users in that group
    the permissions defined by the role's policies.
    """

    queryset = GroupRoleAssignment.objects.select_related("group", "role").all()
    serializer_class = GroupRoleAssignmentSerializer
    permission_classes = try_add_oauth2_scope_permission([IsSuperuser])
    # Assignments are immutable once created
    http_method_names = ["get", "post", "head", "options", "delete"]
    filterset_fields = ["group", "role"]


class UserEffectiveScopeView(AnsibleBaseDjangoAppApiView):
    """Introspect a user's effective OPA scope for a given resource and action.

    GET /opa/effective_scope/?user_id=<pk>&resource=<name>&action=<action>

    Returns the resolved clauses that would be applied to filter the queryset.
    Useful for debugging and understanding what a user can access.
    """

    permission_classes = try_add_oauth2_scope_permission([IsSuperuser])
    serializer_class = UserEffectiveScopeSerializer

    def get(self, request):
        user_id = request.query_params.get("user_id")
        resource = request.query_params.get("resource")
        action_param = request.query_params.get("action")

        if not all([user_id, resource, action_param]):
            return Response(
                {"detail": "Required query params: user_id, resource, action"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            opa_registry.get_resource(resource)
        except ValueError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        User = get_user_model()
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return Response(
                {"detail": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        scope = local_get_scope(user, resource, action_param)
        data = {
            "resource": resource,
            "action": action_param,
            "allow": scope["allow"],
            "clauses": scope["clauses"],
        }
        serializer = UserEffectiveScopeSerializer(data)
        return Response(serializer.data)
