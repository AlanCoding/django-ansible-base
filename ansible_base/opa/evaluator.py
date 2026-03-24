import logging
from collections import defaultdict

from django.db.models import Q

from ansible_base.opa.queryset import compile_clauses
from ansible_base.opa.registry import opa_registry

logger = logging.getLogger(__name__)


def get_effective_policies(user, resource, action):
    """Resolve a user's effective policies for a resource/action purely in Django.

    Traverses: user -> dab_opa_groups -> role_assignments -> roles -> policies
    Filters by resource and action, then resolves principal_user_id.

    Returns a list of resolved clause dicts matching the OPA response format:
        [{"field_name": "...", "operator": "...", "value": ...}, ...]
    """
    from ansible_base.opa.models import Policy

    # Get all policies reachable through user's OPA groups
    policies = Policy.objects.filter(
        role__group_assignments__group__users=user,
        resource=resource,
        action=action,
    ).distinct()

    seen = set()
    clauses = []
    for p in policies:
        clause = _resolve_policy(p, user)
        key = (clause["field_name"], clause["operator"], clause["value"])
        if key in seen:
            continue
        seen.add(key)
        clauses.append(clause)

    return clauses


def get_unresolved_policies(user, resource, action):
    """Get a user's effective policies as unresolved clause dicts for OPA input.

    Like get_effective_policies but preserves value_type so OPA's Rego can
    perform the resolution (e.g., substituting principal_user_id at eval time).

    Returns a list of clause dicts:
        [{"field_name": "...", "operator": "...", "value_type": "...", "value": ...}, ...]
    """
    from ansible_base.opa.models import Policy

    policies = Policy.objects.filter(
        role__group_assignments__group__users=user,
        resource=resource,
        action=action,
    ).distinct()

    seen = set()
    clauses = []
    for p in policies:
        clause = _unresolved_clause(p)
        key = (clause["field_name"], clause["operator"], clause["value_type"], str(clause.get("value", "")))
        if key in seen:
            continue
        seen.add(key)
        clauses.append(clause)

    return clauses


def _unresolved_clause(policy):
    """Convert a Policy to an unresolved clause dict (preserves value_type)."""
    clause = {
        "field_name": policy.field_name,
        "operator": policy.operator,
        "value_type": policy.value_type,
    }
    if policy.value_type == "constant":
        try:
            clause["value"] = int(policy.constant_value)
        except (ValueError, TypeError):
            clause["value"] = policy.constant_value
    return clause


def _resolve_policy(policy, user):
    """Resolve a single Policy into a clause dict, substituting principal_user_id."""
    if policy.value_type == "principal_user_id":
        return {
            "field_name": policy.field_name,
            "operator": policy.operator,
            "value": user.pk,
        }
    # constant
    try:
        value = int(policy.constant_value)
    except (ValueError, TypeError):
        value = policy.constant_value
    return {
        "field_name": policy.field_name,
        "operator": policy.operator,
        "value": value,
    }


def local_get_scope(user, resource, action):
    """Local equivalent of get_opa_scope — returns same dict format.

    Returns:
        Dict with 'allow' (bool) and 'clauses' (list).
    """
    if user.is_superuser:
        return {"allow": True, "clauses": []}

    clauses = get_effective_policies(user, resource, action)
    return {
        "allow": len(clauses) > 0,
        "clauses": clauses,
    }


def local_filter_queryset(queryset, user, action):
    """Filter a queryset using the local evaluator (no OPA call).

    Same interface as filter_queryset_for_user but resolves policies in Django.
    """
    if user.is_superuser:
        return queryset

    model_cls = queryset.model
    resource_name = opa_registry.get_resource_name_for_model(model_cls)
    clauses = get_effective_policies(user, resource_name, action)
    q = compile_clauses(clauses, resource_name)
    return queryset.filter(q)


def local_user_can_access_obj(user, obj, action):
    """Check object access using the local evaluator (no OPA call).

    Uses tier 2 evaluation: checks user's clauses against the object's
    actual attributes directly, rather than filtering a queryset.
    """
    if user.is_superuser:
        return True

    model_cls = type(obj)
    resource_name = opa_registry.get_resource_name_for_model(model_cls)
    obj_attrs = _extract_obj_attrs(obj, resource_name)
    clauses = get_effective_policies(user, resource_name, action)
    return _clauses_match_object(clauses, obj_attrs)


def local_check_object(user, obj, action, related=None):
    """Tier 2 local evaluation: object access + related object checks.

    Args:
        user: the requesting user
        obj: the Django model instance
        action: the OPA action string
        related: optional dict of field_name -> {resource, action, id, org_id}

    Returns:
        Dict with 'object_allowed' (bool) and 'related_denied' (set of field names).
    """
    if user.is_superuser:
        return {"object_allowed": True, "related_denied": set()}

    model_cls = type(obj)
    resource_name = opa_registry.get_resource_name_for_model(model_cls)
    obj_attrs = _extract_obj_attrs(obj, resource_name)
    clauses = get_effective_policies(user, resource_name, action)
    object_allowed = _clauses_match_object(clauses, obj_attrs)

    related_denied = set()
    if related:
        for field_name, check in related.items():
            if not _check_related_allowed(user, check):
                related_denied.add(field_name)

    return {"object_allowed": object_allowed, "related_denied": related_denied}


def _extract_obj_attrs(obj, resource_name):
    """Extract the registered field values from a model instance."""
    fields = opa_registry.get_fields(resource_name)
    attrs = {}
    for field_name, field_def in fields.items():
        django_path = field_def["django_path"]
        try:
            attrs[field_name] = getattr(obj, django_path)
        except AttributeError:
            pass
    return attrs


def _clauses_match_object(clauses, obj_attrs):
    """Check if any clause matches the object's attributes."""
    for clause in clauses:
        field_name = clause["field_name"]
        operator = clause["operator"]
        value = clause["value"]

        if field_name not in obj_attrs:
            continue

        if operator == "eq" and obj_attrs[field_name] == value:
            return True

    return False


def _check_related_allowed(user, check):
    """Check if user has permission for a related object."""
    resource = check["resource"]
    action = check["action"]
    related_id = check.get("id")
    org_id = check.get("org_id")

    clauses = get_effective_policies(user, resource, action)
    for clause in clauses:
        if clause["operator"] != "eq":
            continue
        # Direct ID match
        if clause["field_name"] == "id" and related_id is not None and clause["value"] == related_id:
            return True
        # Org-scoped match
        if clause["field_name"] == "organization_id" and org_id is not None and clause["value"] == org_id:
            return True
    return False
