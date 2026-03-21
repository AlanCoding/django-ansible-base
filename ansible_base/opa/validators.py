import logging

from django.core.exceptions import ValidationError

from ansible_base.lib.opa.models.policy import Policy
from ansible_base.lib.opa.registry import opa_registry

logger = logging.getLogger(__name__)


def validate_policy(policy):
    """Validate a Policy instance against the registry and Django model metadata.

    Validates resource, action, field_name, operator, and value (constant coercion
    or principal_user_id rules). Raises ValidationError with a dict of field errors.
    """
    errors = {}

    # 3.1 Registry validation: resource
    try:
        opa_registry.get_resource(policy.resource)
    except ValueError as e:
        errors["resource"] = str(e)
        # Can't validate further without a valid resource
        raise ValidationError(errors)

    # 3.1 Registry validation: action
    valid_actions = opa_registry.get_actions(policy.resource)
    if policy.action not in valid_actions:
        errors["action"] = (
            f"Invalid action '{policy.action}' for resource '{policy.resource}'. "
            f"Valid actions: {valid_actions}"
        )

    # 3.1 Registry validation: field_name
    try:
        field_def = opa_registry.get_field(policy.resource, policy.field_name)
    except ValueError as e:
        errors["field_name"] = str(e)
        field_def = None

    # 3.1 Registry validation: operator
    if field_def is not None:
        allowed_ops = field_def.get("operators", [])
        if policy.operator not in allowed_ops:
            errors["operator"] = (
                f"Invalid operator '{policy.operator}' for field '{policy.field_name}'. "
                f"Allowed operators: {allowed_ops}"
            )

    # 3.2 Value validation
    if policy.value_type == Policy.ValueType.PRINCIPAL_USER_ID:
        if policy.constant_value not in (None, ""):
            errors["constant_value"] = (
                "constant_value must be blank when value_type is 'principal_user_id'."
            )
    elif policy.value_type == Policy.ValueType.CONSTANT:
        if policy.constant_value in (None, ""):
            errors["constant_value"] = (
                "constant_value is required when value_type is 'constant'."
            )
        elif field_def is not None:
            # Coerce and validate against the actual Django model field
            coercion_error = _validate_constant_value(policy.resource, field_def, policy.constant_value)
            if coercion_error:
                errors["constant_value"] = coercion_error

    if errors:
        raise ValidationError(errors)


def _validate_constant_value(resource_name, field_def, raw_value):
    """Validate and coerce constant_value against the actual Django model field.

    Returns an error string if invalid, or None if valid.
    """
    model_cls = opa_registry.get_model(resource_name)
    django_path = field_def["django_path"]

    # Resolve the Django field from the model
    try:
        django_field = model_cls._meta.get_field(django_path)
    except Exception:
        return f"Cannot resolve Django field '{django_path}' on model {model_cls.__name__}."

    # Use Django's field to coerce the value
    try:
        django_field.get_prep_value(django_field.to_python(raw_value))
    except (ValueError, TypeError, ValidationError) as e:
        return (
            f"Invalid value '{raw_value}' for field '{django_path}' "
            f"on {model_cls.__name__}: {e}"
        )

    return None


def validate_role_dependencies(role, strict=None):
    """Validate action dependencies for all policies in a role.

    In strict mode: raises ValidationError if required dependent policies are missing.
    In loose mode: returns a list of Policy instances that should be auto-added.

    Args:
        role: Role instance whose policies to check
        strict: True for strict mode, False for loose mode, None for setting default

    Returns:
        List of Policy instances to auto-add (empty in strict mode).

    Raises:
        ValidationError in strict mode when dependencies are missing.
    """
    if strict is None:
        strict = opa_registry.strict_mode_default

    policies = list(role.policies.all())
    return check_dependency_policies(policies, strict=strict)


def check_dependency_policies(policies, strict=True):
    """Check action dependencies across a list of policies.

    Args:
        policies: list of Policy instances (or unsaved Policy-like objects)
        strict: if True, raise ValidationError on missing deps; if False, return auto-adds

    Returns:
        List of Policy-like dicts to auto-add (empty in strict mode).
    """
    # Index existing policies by (resource, action, field_name, operator, value_type, constant_value)
    existing = set()
    for p in policies:
        existing.add(_policy_key(p))

    missing = []
    for p in policies:
        deps = opa_registry.get_action_dependencies(p.resource)
        required_actions = deps.get(p.action, [])
        for req_action in required_actions:
            dep_key = (p.resource, req_action, p.field_name, p.operator, p.value_type, p.constant_value)
            if dep_key not in existing:
                missing.append({
                    "resource": p.resource,
                    "action": req_action,
                    "field_name": p.field_name,
                    "operator": p.operator,
                    "value_type": p.value_type,
                    "constant_value": p.constant_value,
                    "required_by": f"{p.resource}.{p.action}",
                })

    if not missing:
        return []

    if strict:
        details = "; ".join(
            f"{m['resource']}.{m['action']} (required by {m['required_by']})"
            for m in missing
        )
        raise ValidationError(
            f"Missing required dependent policies: {details}. "
            f"Add them explicitly or use loose mode to auto-add."
        )

    # Loose mode: return Policy instances to be created
    auto_add = []
    for m in missing:
        auto_add.append({
            "resource": m["resource"],
            "action": m["action"],
            "field_name": m["field_name"],
            "operator": m["operator"],
            "value_type": m["value_type"],
            "constant_value": m["constant_value"],
        })
        # Add to existing set so we don't duplicate
        key = (m["resource"], m["action"], m["field_name"], m["operator"], m["value_type"], m["constant_value"])
        existing.add(key)

    return auto_add


def _policy_key(policy):
    """Return a hashable key identifying a policy's logical identity."""
    return (
        policy.resource,
        policy.action,
        policy.field_name,
        policy.operator,
        policy.value_type,
        policy.constant_value,
    )
