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

    Authorization is split across two layers, matching DAB RBAC's pattern:

    1. **Permission class (this class)** — consulted by DRF before request
       data is available. Answers coarse-grained questions: "is this user
       authenticated?", "do they have any add scope at all?", "can they
       access this specific object?" This layer uses tier 1 (queryset
       filtering) for capability checks and tier 2 (object evaluation) for
       object-level checks.

    2. **Serializer mixin (OPARelatedAccessMixin)** — runs inside
       create()/update() after the object is saved in a transaction.
       Answers fine-grained questions: "can they create in THIS org?",
       "can they use THIS credential?" This layer performs the actual
       related object permission checks and rolls back on denial.

    This separation exists because DRF's permission class is also called
    by schema generators (e.g., DRF Spectacular) and OPTIONS requests with
    mock requests that have no request body. The permission class cannot
    inspect which org or credential the user intends to use — that data
    only exists at serializer time. So has_permission() answers "does the
    user have the capability?" and the serializer enforces "do they have
    permission for these specific related objects?"
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
        """Check if user has the *capability* to create objects of this type.

        This intentionally uses tier 1 queryset filtering + .exists(), NOT
        tier 2 object evaluation. The distinction matters:

        - Tier 2 requires a concrete object with specific attributes (which
          org? which credential?). At has_permission() time, the object
          doesn't exist yet and request data may not be available (schema
          generators and OPTIONS requests use mock requests with no body).

        - Tier 1 queryset filtering answers the coarser question: "does this
          user have ANY add scope for this resource?" If the user has an
          add policy scoped to organization_id=5, the filtered queryset
          will include objects in org 5, and .exists() returns True —
          confirming the user has add capability somewhere.

        The actual authorization of "can they create in THIS specific org
        with THIS specific credential?" is deferred to the serializer layer
        (OPARelatedAccessMixin), which runs inside create() after the object
        is constructed and can inspect the concrete FK values.

        This matches DAB RBAC's architecture where:
        - AnsibleBaseObjectPermissions.has_permission() checks broad capability
        - RelatedAccessMixin.create() checks specific related objects
        """
        queryset = view.get_queryset()
        model_cls = queryset.model

        if not _is_opa_resource(model_cls):
            return True

        resource_name = opa_registry.get_resource_name_for_model(model_cls)
        actions = opa_registry.get_actions(resource_name)
        if "add" not in actions:
            return True

        # Use tier 1 (queryset filtering) to check if user has any add scope.
        # This is a capability check, not an authorization decision — the
        # authoritative related-object check happens at the serializer layer.
        qs = filter_queryset_for_user(model_cls.objects.all(), request.user, "add")
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
