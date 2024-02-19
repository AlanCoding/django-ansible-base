from django.http import Http404
from rest_framework.permissions import SAFE_METHODS, BasePermission, DjangoObjectPermissions

from ansible_base.rbac import permission_registry
from ansible_base.rbac.evaluations import has_super_permission


class IsSystemAdminOrAuditor(BasePermission):
    """
    Allows write access only to system admin users.
    Allows read access only to system auditor users.
    """

    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        if request.method in SAFE_METHODS:
            return has_super_permission(request.user, 'view')
        return has_super_permission(request.user)


class AuthenticatedReadAdminChange(IsSystemAdminOrAuditor):
    "Any authenticated user can view, but only admin users can do CRUD"

    def has_permission(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return False
        if request.method in SAFE_METHODS:
            return True
        return has_super_permission(request.user)


class AnsibleBaseObjectPermissions(DjangoObjectPermissions):

    def has_permission(self, request, view):
        "Half of this comes from ModelAccessPermission. We assume user.permissions is unused"
        if not request.user or (not request.user.is_authenticated and self.authenticated_users_only):
            return False

        # Workaround to ensure DjangoModelPermissions are not applied
        # to the root view when using DefaultRouter.
        if getattr(view, '_ignore_model_permissions', False):
            return True

        if request.method == 'POST':
            queryset = self._queryset(view)
            model_cls = queryset.model
            parent_field_name = permission_registry.get_parent_fd_name(model_cls)
            parent_model = permission_registry.get_parent_model(model_cls)
            parent_obj = parent_model.objects.get(pk=request.data[parent_field_name])
            return request.user.has_obj_perm(parent_obj, f'add_{model_cls._meta.model_name}')

        # As an exception to this, AWX calls access methods with None in place of data
        # which results in POST or PUT being excluded from OPTIONS for permissions reasons
        return True

    def has_object_permission(self, request, view, obj):
        "Original version of this comes from DjangoModelPermissions, overridden to use has_obj_perm"
        queryset = self._queryset(view)
        model_cls = queryset.model
        user = request.user

        perms = self.get_required_object_permissions(request.method, model_cls)

        if not all(user.has_obj_perm(obj, perm) for perm in perms):
            # If the user does not have permissions we need to determine if
            # they have read permissions to see 403, or not, and simply see
            # a 404 response.

            if request.method in SAFE_METHODS:
                # Read permissions already checked and failed, no need
                # to make another lookup.
                raise Http404

            read_perms = self.get_required_object_permissions('GET', model_cls)
            if not all(user.has_obj_perm(obj, perm) for perm in read_perms):
                raise Http404

            # Has read permissions.
            return False

        return True
