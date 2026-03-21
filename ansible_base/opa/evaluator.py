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

    Same interface as user_can_access_obj.
    """
    if user.is_superuser:
        return True

    model_cls = type(obj)
    resource_name = opa_registry.get_resource_name_for_model(model_cls)
    clauses = get_effective_policies(user, resource_name, action)
    q = compile_clauses(clauses, resource_name)
    return model_cls.objects.filter(q, pk=obj.pk).exists()
