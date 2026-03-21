import logging

from django.http import Http404
from rest_framework.permissions import SAFE_METHODS, BasePermission

from ansible_base.opa.queryset import filter_queryset_for_user, user_can_access_obj
from ansible_base.opa.registry import opa_registry

logger = logging.getLogger(__name__)

# Map HTTP methods to OPA actions
METHOD_ACTION_MAP = {
    "GET": "read",
    "HEAD": "read",
    "OPTIONS": "read",
    "POST": "add",
    "PUT": "change",
    "PATCH": "change",
    "DELETE": "delete",
}


def _get_action_for_request(request, view):
    """Determine the OPA action for a given request/view."""
    special_action = getattr(view, "opa_action", None)
    if special_action:
        return special_action
    return METHOD_ACTION_MAP.get(request.method, "read")


def _is_opa_resource(model_cls):
    """Check if a model is registered in the OPA registry."""
    try:
        opa_registry.get_resource_name_for_model(model_cls)
        return True
    except ValueError:
        return False


class OPAPermission(BasePermission):
    """DRF permission class that delegates to OPA for authorization.

    Drop-in replacement for AnsibleBaseObjectPermissions.
    Uses OPA queryset filtering for list views and object-level checks for detail views.
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        if request.user.is_superuser:
            return True

        # For create actions, check if user has add permission on any parent object
        if request.method == "POST" and getattr(view, "action", None) == "create":
            return self._has_create_permission(request, view)

        return True

    def _has_create_permission(self, request, view):
        """Check if user can create objects of this type.

        For models with a parent (organization), checks if the user has 'add'
        permission on at least one parent object. For root-level models,
        only superusers can create.
        """
        queryset = view.get_queryset()
        model_cls = queryset.model

        if not _is_opa_resource(model_cls):
            return True

        resource_name = opa_registry.get_resource_name_for_model(model_cls)
        actions = opa_registry.get_actions(resource_name)
        if "add" not in actions:
            return True

        # Check if user has any 'add' clauses for this resource
        qs = filter_queryset_for_user(model_cls.objects.all(), request.user, "add")
        # For add permission, we check if the user has any scope at all
        # (the queryset will be non-empty if they have add permission somewhere)
        return qs.exists()

    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False

        if request.user.is_superuser:
            return True

        if not _is_opa_resource(type(obj)):
            logger.warning(
                "OPA permission check on unregistered model %s, denying",
                type(obj).__name__,
            )
            raise Http404

        action = _get_action_for_request(request, view)

        if not user_can_access_obj(request.user, obj, action):
            if request.method in SAFE_METHODS:
                raise Http404
            # Check if user can at least read the object (403 vs 404)
            if not user_can_access_obj(request.user, obj, "read"):
                raise Http404
            return False

        return True
