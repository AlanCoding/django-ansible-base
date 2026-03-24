import logging

logger = logging.getLogger(__name__)


def recompute_team_memberships():
    """Ensure users who can modify teams are members of those teams' OPA groups.

    If a user has a policy granting 'change' on 'team' scoped to an org, they
    can add themselves to any team in that org (and thus acquire team permissions).
    To match RBAC behavior, we proactively add these users to all team OPA groups
    in the org so they inherit team permissions immediately.

    This function is idempotent.
    """
    from collections import defaultdict

    from django.conf import settings as django_settings

    from ansible_base.opa.models import GroupRoleAssignment, OPAGroup, Policy

    # Find all policies that grant 'change' on 'team' — these users can modify teams
    team_change_policies = Policy.objects.filter(
        resource="team",
        action="change",
        field_name="organization_id",
        value_type="constant",
    ).select_related("role")

    if not team_change_policies.exists():
        return

    # Build mapping: org_id -> set of user PKs who can modify teams in that org
    org_to_users = defaultdict(set)
    for policy in team_change_policies:
        org_id = policy.constant_value
        # Find all users who have this policy through role -> group -> users
        assignments = GroupRoleAssignment.objects.filter(role=policy.role).select_related("group")
        for assignment in assignments:
            for user in assignment.group.users.all():
                org_to_users[org_id].add(user)

    if not org_to_users:
        return

    # Find the team model via settings
    try:
        from django.apps import apps as django_apps

        team_model_path = getattr(django_settings, "ANSIBLE_BASE_TEAM_MODEL", None)
        if not team_model_path:
            return
        team_model = django_apps.get_model(team_model_path)
    except Exception:
        return

    # Determine the org FK field on the team model
    org_model_path = getattr(django_settings, "ANSIBLE_BASE_ORGANIZATION_MODEL", "")
    org_field = None
    for field in team_model._meta.get_fields():
        if hasattr(field, "related_model") and field.related_model:
            model_path = f"{field.related_model._meta.app_label}.{field.related_model._meta.model_name}"
            if model_path.lower() == org_model_path.lower():
                org_field = field.name
                break

    if not org_field:
        return

    # For each org, ensure all team-modifying users are in all team OPA groups
    added = 0
    for org_id_str, users in org_to_users.items():
        teams = team_model.objects.filter(**{f"{org_field}_id": org_id_str})
        for team in teams:
            group_name = f"team:{team.name}"
            org = getattr(team, org_field, None)
            group, _ = OPAGroup.objects.get_or_create(
                name=group_name,
                defaults={"managed": True, "organization": org},
            )
            for user in users:
                if not group.users.filter(pk=user.pk).exists():
                    group.users.add(user)
                    added += 1

    if added:
        logger.info("Team membership recompute: added %d user-group memberships", added)
