import logging

from django.db.models import Q

from ansible_base.opa.registry import opa_registry

logger = logging.getLogger(__name__)

# Operator mapping from OPA clause operator to Django ORM lookup
_OPERATOR_MAP = {
    "eq": "",  # Django default lookup is exact match (field=value)
}


def compile_clauses(clauses, resource_name):
    """Compile a list of resolved OPA clauses into a Django Q expression.

    Each clause is OR'd together. Returns Q() that matches nothing if
    clauses is empty.

    Args:
        clauses: list of dicts with 'field_name', 'operator', 'value'
        resource_name: the OPA resource name (for field path resolution)

    Returns:
        A Django Q object.
    """
    if not clauses:
        return Q(pk__in=[])  # matches nothing

    q = Q()
    for clause in clauses:
        field_name = clause["field_name"]
        operator = clause["operator"]
        value = clause["value"]

        # Resolve django_path from registry
        field_def = opa_registry.get_field(resource_name, field_name)
        django_path = field_def["django_path"]

        # Build the ORM lookup
        suffix = _OPERATOR_MAP.get(operator)
        if suffix is None:
            logger.warning("Unknown operator '%s', skipping clause", operator)
            continue

        if suffix:
            lookup = f"{django_path}__{suffix}"
        else:
            lookup = django_path

        q = q | Q(**{lookup: value})

    return q


def filter_queryset_for_user(queryset, user, action):
    """Filter a queryset to only include objects the user can access.

    Resolves the user's effective policies for the queryset's model and
    the given action, then applies them as queryset filters.

    When DAB_OPA_TRANSITION_VALIDATION is enabled, also compares the
    result against RBAC and logs discrepancies.

    Args:
        queryset: a Django QuerySet
        user: the user requesting access
        action: the action string (e.g. 'read', 'change', 'delete')

    Returns:
        Filtered QuerySet.
    """
    if user.is_superuser:
        return queryset

    model_cls = queryset.model
    resource_name = opa_registry.get_resource_name_for_model(model_cls)
    result = get_opa_scope(user, resource_name, action)
    q = compile_clauses(result["clauses"], resource_name)
    filtered = queryset.filter(q)

    from ansible_base.opa.transition import validate_queryset_filter

    return validate_queryset_filter(filtered, user, action)


def user_can_access_obj(user, obj, action, related=None):
    """Check if a user can perform an action on a specific object.

    Uses tier 2 OPA evaluation: sends the object's attributes and the
    user's policies to OPA for a concrete boolean answer. Optionally
    checks related objects.

    When DAB_OPA_TRANSITION_VALIDATION is enabled, also compares the
    result against RBAC and logs discrepancies.

    Args:
        user: the user requesting access
        obj: the Django model instance
        action: the action string
        related: optional dict of field_name -> {resource, action, id, org_id}

    Returns:
        True if the user can access the object, False otherwise.
    """
    if user.is_superuser:
        return True

    model_cls = type(obj)
    resource_name = opa_registry.get_resource_name_for_model(model_cls)
    result = check_object_access(user, resource_name, action, obj, related)
    opa_result = result["object_allowed"] and not result["related_denied"]

    from ansible_base.opa.transition import validate_object_access

    return validate_object_access(opa_result, user, obj, action)


def check_object_access(user, resource, action, obj, related=None):
    """Tier 2: Check object access via OPA with the object's actual attributes.

    Resolves the user's policies and sends them along with the object
    attributes to OPA for evaluation.

    Args:
        user: the user
        resource: OPA resource name
        action: OPA action string
        obj: the Django model instance
        related: optional dict of field_name -> {resource, action, id, org_id}

    Returns:
        Dict with 'object_allowed' (bool) and 'related_denied' (set of field names).
    """
    from ansible_base.opa.client import OPAClient
    from ansible_base.opa.evaluator import _extract_obj_attrs, get_unresolved_policies

    obj_attrs = _extract_obj_attrs(obj, resource)
    policies = get_unresolved_policies(user, resource, action)

    # Resolve policies for each related entry
    opa_related = None
    if related:
        opa_related = {}
        for field_name, check in related.items():
            rel_policies = get_unresolved_policies(user, check["resource"], check["action"])
            opa_related[field_name] = {
                **check,
                "policies": rel_policies,
            }

    client = OPAClient(base_url=opa_registry.server_url)
    return client.check_object(
        user_id=user.pk,
        is_superuser=user.is_superuser,
        resource=resource,
        action=action,
        obj_attrs=obj_attrs,
        policies=policies,
        related=opa_related,
    )


def get_opa_scope(user, resource, action):
    """Get the OPA scope (resolved clauses) for a user/resource/action.

    Resolves the user's policies and sends them to OPA for clause resolution
    (e.g., principal_user_id substitution).

    Args:
        user: the user (or any object with .pk and .is_superuser)
        resource: the OPA resource name string
        action: the action string

    Returns:
        Dict with 'allow' (bool) and 'clauses' (list).
    """
    from ansible_base.opa.client import OPAClient
    from ansible_base.opa.evaluator import get_unresolved_policies

    policies = get_unresolved_policies(user, resource, action)
    client = OPAClient(base_url=opa_registry.server_url)
    return client.query(
        user_id=user.pk,
        is_superuser=user.is_superuser,
        resource=resource,
        action=action,
        policies=policies,
    )
