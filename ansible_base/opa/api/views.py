import logging

from django.contrib.auth import get_user_model
from rest_framework import permissions, status
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
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
from ansible_base.opa.delegation import (
    validate_user_can_delegate_policy,
    validate_user_can_delegate_role,
)
from ansible_base.opa.evaluator import local_get_scope
from ansible_base.opa.models import GroupRoleAssignment, OPAGroup, Policy, Role
from ansible_base.opa.permissions import OPAPermission
from ansible_base.opa.queryset import filter_queryset_for_user, user_can_access_obj
from ansible_base.opa.registry import opa_registry

logger = logging.getLogger(__name__)


class OPAGroupPermission(OPAPermission):
    """OPA permission class for OPAGroup viewset.

    Uses OPA-based authorization so that group management is gated by
    opagroup.change policies (team admin, org admin).
    """

    pass


class RoleViewSet(AnsibleBaseDjangoAppApiView, ModelViewSet):
    """Manage OPA roles.

    Roles contain policies that define what resources and actions are granted.
    Any authenticated user can create a role. Only the creator (or superuser)
    can update or delete non-managed roles.
    """

    queryset = Role.objects.prefetch_related("policies").all()
    serializer_class = RoleSerializer
    permission_classes = try_add_oauth2_scope_permission([permissions.IsAuthenticated])

    def get_serializer_class(self):
        if self.action in ("update", "partial_update"):
            return RoleDetailSerializer
        return RoleSerializer

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    def perform_update(self, serializer):
        instance = self.get_object()
        if instance.managed and not self.request.user.is_superuser:
            raise PermissionDenied("Cannot modify a managed role.")
        if not self.request.user.is_superuser and instance.created_by != self.request.user:
            raise PermissionDenied("Only the role creator or a superuser can modify this role.")
        serializer.save()

    def perform_destroy(self, instance):
        if instance.managed and not self.request.user.is_superuser:
            raise PermissionDenied("Cannot delete a managed role.")
        if not self.request.user.is_superuser and instance.created_by != self.request.user:
            raise PermissionDenied("Only the role creator or a superuser can delete this role.")
        super().perform_destroy(instance)


class PolicyViewSet(AnsibleBaseDjangoAppApiView, ModelViewSet):
    """Manage OPA policies.

    Policies are immutable — create and delete only, no updates.
    Creating a policy requires `change` access covering the policy's scope.
    """

    queryset = Policy.objects.select_related("role").all()
    serializer_class = PolicySerializer
    permission_classes = try_add_oauth2_scope_permission([permissions.IsAuthenticated])
    filterset_fields = ["role", "resource", "action"]
    http_method_names = ["get", "post", "head", "options", "delete"]

    def perform_create(self, serializer):
        policy = Policy(**serializer.validated_data)
        allowed, reason = validate_user_can_delegate_policy(self.request.user, policy)
        if not allowed:
            raise PermissionDenied(reason)
        serializer.save()

    def perform_destroy(self, instance):
        allowed, reason = validate_user_can_delegate_policy(self.request.user, instance)
        if not allowed:
            raise PermissionDenied(reason)
        super().perform_destroy(instance)


class OPAGroupViewSet(AnsibleBaseDjangoAppApiView, ModelViewSet):
    """Manage OPA groups.

    Groups contain users and can have roles assigned to them.
    Access is controlled by OPA policies on the `opagroup` resource.
    """

    queryset = OPAGroup.objects.prefetch_related("users").all()
    serializer_class = OPAGroupSerializer
    permission_classes = try_add_oauth2_scope_permission([permissions.IsAuthenticated, OPAGroupPermission])

    def filter_queryset(self, qs):
        """Filter groups to those the user can read."""
        user = self.request.user
        if not user.is_superuser:
            try:
                opa_registry.get_resource_name_for_model(OPAGroup)
                qs = filter_queryset_for_user(qs, user, "read")
            except ValueError:
                pass
        return super().filter_queryset(qs)

    def perform_destroy(self, instance):
        if instance.managed:
            raise PermissionDenied("Cannot delete a managed group.")
        super().perform_destroy(instance)

    @action(detail=True, methods=["post"], url_path="add_user")
    def add_user(self, request, pk=None):
        """Add a user to this group."""
        self.opa_action = "change"
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
        self.opa_action = "change"
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

    Assigning a role to a group requires:
    1. `change` on the group (you can manage it)
    2. `change` covering all policies in the role (you can delegate them)
    """

    queryset = GroupRoleAssignment.objects.select_related("group", "role").all()
    serializer_class = GroupRoleAssignmentSerializer
    permission_classes = try_add_oauth2_scope_permission([permissions.IsAuthenticated])
    http_method_names = ["get", "post", "head", "options", "delete"]
    filterset_fields = ["group", "role"]

    def perform_create(self, serializer):
        group = serializer.validated_data["group"]
        role = serializer.validated_data["role"]
        user = self.request.user

        # Gate 1: user must have change on the group
        if not user.is_superuser and not user_can_access_obj(user, group, "change"):
            raise PermissionDenied("You do not have change access to this group.")

        # Gate 2: user must be able to delegate all policies in the role
        allowed, reason = validate_user_can_delegate_role(user, role)
        if not allowed:
            raise PermissionDenied(reason)

        serializer.save()

    def perform_destroy(self, instance):
        user = self.request.user
        if not user.is_superuser and not user_can_access_obj(user, instance.group, "change"):
            raise PermissionDenied("You do not have change access to this group.")
        super().perform_destroy(instance)


class UserEffectiveScopeView(AnsibleBaseDjangoAppApiView):
    """Introspect a user's effective OPA scope for a given resource and action.

    GET /opa/effective_scope/?user_id=<pk>&resource=<name>&action=<action>

    Returns the resolved clauses that would be applied to filter the queryset.
    Useful for debugging and understanding what a user can access.
    """

    permission_classes = try_add_oauth2_scope_permission([permissions.IsAuthenticated])
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
