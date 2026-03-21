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

    Uses OPA to resolve the user's effective clauses for the queryset's
    model and the given action, then applies them as queryset filters.

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
    return queryset.filter(q)


def user_can_access_obj(user, obj, action):
    """Check if a user can perform an action on a specific object.

    Derived from queryset filtering — not separate logic.

    Args:
        user: the user requesting access
        obj: the Django model instance
        action: the action string

    Returns:
        True if the user can access the object, False otherwise.
    """
    if user.is_superuser:
        return True

    model_cls = type(obj)
    resource_name = opa_registry.get_resource_name_for_model(model_cls)
    result = get_opa_scope(user, resource_name, action)
    q = compile_clauses(result["clauses"], resource_name)

    return model_cls.objects.filter(q, pk=obj.pk).exists()


def get_opa_scope(user, resource, action):
    """Get the raw OPA response for a user/resource/action.

    Args:
        user: the user (or any object with .pk and .is_superuser)
        resource: the OPA resource name string
        action: the action string

    Returns:
        Dict with 'allow' (bool) and 'clauses' (list).
    """
    from ansible_base.opa.client import OPAClient

    client = OPAClient(base_url=opa_registry.server_url)
    return client.query(
        user_id=user.pk,
        is_superuser=user.is_superuser,
        resource=resource,
        action=action,
    )
