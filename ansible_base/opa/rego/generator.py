import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


def generate_user_policies():
    """Generate the flattened user_policies data structure for OPA.

    Resolves: user -> groups -> roles -> policies
    Pre-flattens everything so OPA does a simple lookup by user_id/resource/action.

    Returns a dict suitable for pushing to OPA as data.dab_opa.user_policies:
    {
        "<user_id>": {
            "<resource>": {
                "<action>": [
                    {"field_name": "...", "operator": "...", "value_type": "...", "value": ...},
                    ...
                ]
            }
        }
    }
    """
    from ansible_base.lib.opa.models import OPAGroup

    # user_id -> resource -> action -> list of clause dicts
    user_policies = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

    # Track dedup per user/resource/action to avoid duplicate clauses
    seen = set()

    groups = (
        OPAGroup.objects.prefetch_related(
            "users",
            "role_assignments__role__policies",
        ).all()
    )

    for group in groups:
        # Collect all policies from all roles assigned to this group
        policies = []
        for assignment in group.role_assignments.all():
            for policy in assignment.role.policies.all():
                policies.append(policy)

        if not policies:
            continue

        # Apply each policy to each user in the group
        for user in group.users.all():
            uid = str(user.pk)
            for policy in policies:
                clause = _policy_to_clause(policy)
                clause_key = (policy.resource, policy.action, clause["field_name"], clause["operator"], clause["value_type"], str(clause.get("value", "")))

                dedup_key = (uid, *clause_key)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                user_policies[uid][policy.resource][policy.action].append(clause)

    # Convert nested defaultdicts to plain dicts for JSON serialization
    result = {}
    for uid, resources in user_policies.items():
        result[uid] = {}
        for resource, actions in resources.items():
            result[uid][resource] = {}
            for action, clauses in actions.items():
                result[uid][resource][action] = clauses

    logger.info(
        "Generated OPA policy data: %d users, %d total clauses",
        len(result),
        sum(
            len(clauses)
            for resources in result.values()
            for actions in resources.values()
            for clauses in actions.values()
        ),
    )

    return result


def _policy_to_clause(policy):
    """Convert a Policy model instance to an OPA clause dict."""
    clause = {
        "field_name": policy.field_name,
        "operator": policy.operator,
        "value_type": policy.value_type,
    }
    if policy.value_type == "constant":
        # Coerce to int if possible (OPA works with native types)
        try:
            clause["value"] = int(policy.constant_value)
        except (ValueError, TypeError):
            clause["value"] = policy.constant_value
    return clause
