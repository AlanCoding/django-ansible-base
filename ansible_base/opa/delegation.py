"""Delegation validation for OPA management endpoints.

Implements the rule: you can delegate access to any resource you have
`change` on. Validates that a user's existing access covers the scope
of the policy they're creating or the role they're assigning.
"""

import logging

from ansible_base.opa.evaluator import get_effective_policies
from ansible_base.opa.queryset import user_can_access_obj
from ansible_base.opa.registry import opa_registry

logger = logging.getLogger(__name__)


def validate_user_can_delegate_policy(user, policy):
    """Check that a user has `change` access covering a policy's scope.

    Args:
        user: the user attempting to create/delegate the policy
        policy: a Policy instance (or unsaved Policy with fields set)

    Returns:
        (True, None) if allowed, (False, reason_string) if not.
    """
    if user.is_superuser:
        return True, None

    resource = policy.resource
    field_name = policy.field_name

    # principal_user_id policies are superuser-only
    if policy.value_type == "principal_user_id":
        return False, "Only superusers can create principal_user_id policies."

    # The user must have `change` on the resource at a scope that covers the policy
    try:
        value = int(policy.constant_value)
    except (ValueError, TypeError):
        value = policy.constant_value

    if field_name == "id":
        # Object-scoped: user must have change on the specific object
        return _validate_object_scope(user, resource, value)
    elif field_name == "organization_id":
        # Org-scoped: user must have org-scoped change for that org
        return _validate_org_scope(user, resource, value)
    else:
        # Other field scopes: user must have change that covers this
        # For now, require org-scoped or broader change
        return _validate_field_scope(user, resource, field_name, value)


def _validate_object_scope(user, resource, obj_pk):
    """Validate user has change on a specific object."""
    try:
        model_cls = opa_registry.get_model(resource)
        obj = model_cls.objects.get(pk=obj_pk)
    except model_cls.DoesNotExist:
        return False, f"Object {resource} pk={obj_pk} does not exist."
    except Exception:
        return False, f"Could not resolve object for {resource} pk={obj_pk}."

    if user_can_access_obj(user, obj, "change"):
        return True, None

    return False, f"You do not have change access to {resource} pk={obj_pk}."


def _validate_org_scope(user, resource, org_id):
    """Validate user has org-scoped change for a resource in the given org.

    An id-scoped change on one object in the org is NOT sufficient to
    create an org-scoped policy — that would be privilege escalation.
    """
    user_change_clauses = get_effective_policies(user, resource, "change")
    for clause in user_change_clauses:
        if clause["operator"] != "eq":
            continue
        if clause["field_name"] == "organization_id" and clause["value"] == org_id:
            return True, None

    return False, f"You do not have org-scoped change access to {resource} in organization {org_id}."


def _validate_field_scope(user, resource, field_name, value):
    """Validate user has change access covering a field-scoped policy."""
    user_change_clauses = get_effective_policies(user, resource, "change")
    for clause in user_change_clauses:
        if clause["operator"] != "eq":
            continue
        # Exact match on the same field
        if clause["field_name"] == field_name and clause["value"] == value:
            return True, None
        # Org-scoped change covers any narrower field
        if clause["field_name"] == "organization_id":
            return True, None

    return False, f"You do not have change access covering {resource}.{field_name}={value}."


def validate_user_can_delegate_role(user, role):
    """Check that a user has `change` access covering all policies in a role.

    Args:
        user: the user attempting to assign the role
        role: a Role instance

    Returns:
        (True, None) if allowed, (False, reason_string) if not.
    """
    if user.is_superuser:
        return True, None

    for policy in role.policies.all():
        allowed, reason = validate_user_can_delegate_policy(user, policy)
        if not allowed:
            return False, f"Cannot delegate role '{role.name}': {reason}"

    return True, None
