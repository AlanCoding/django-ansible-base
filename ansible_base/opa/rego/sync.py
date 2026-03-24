import json
import logging
import os
import threading

import requests

from ansible_base.opa.rego.generator import generate_user_policies

logger = logging.getLogger(__name__)

_sync_lock = threading.Lock()
_sync_timer = None

BUNDLES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "bundles")


def sync_to_opa(debounce_seconds=0):
    """Sync generated policy data to OPA.

    Args:
        debounce_seconds: if > 0, debounce rapid calls by waiting this many
            seconds before actually syncing. Only the last call within the
            window takes effect.
    """
    if debounce_seconds > 0:
        _debounced_sync(debounce_seconds)
    else:
        _do_sync()


def _debounced_sync(seconds):
    """Schedule a sync after a delay, canceling any pending sync."""
    global _sync_timer
    with _sync_lock:
        if _sync_timer is not None:
            _sync_timer.cancel()
        _sync_timer = threading.Timer(seconds, _do_sync)
        _sync_timer.daemon = True
        _sync_timer.start()


def _do_sync():
    """Generate policy data and push to OPA."""
    global _sync_timer
    with _sync_lock:
        _sync_timer = None

    # Ensure org-admin-like users are members of team OPA groups
    recompute_team_memberships()

    user_policies = generate_user_policies()

    # Write data.json to bundles dir for reference/debugging
    _write_data_json(user_policies)

    # Push to OPA via Data API
    _push_to_opa(user_policies)


def recompute_team_memberships():
    """Ensure users who can modify teams are members of those teams' OPA groups.

    If a user has a policy granting 'change' on 'team' scoped to an org, they
    can add themselves to any team in that org (and thus acquire team permissions).
    To match RBAC behavior, we proactively add these users to all team OPA groups
    in the org so they inherit team permissions immediately.

    This function is idempotent and runs before every OPA sync.
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


def _write_data_json(user_policies):
    """Write the generated data to bundles/data.json for reference."""
    data = {"dab_opa": {"user_policies": user_policies}}
    data_path = os.path.join(BUNDLES_DIR, "data.json")
    try:
        with open(data_path, "w") as f:
            json.dump(data, f, indent=2)
        logger.debug("Wrote OPA data to %s", data_path)
    except OSError:
        logger.exception("Failed to write OPA data.json")


def _push_to_opa(user_policies):
    """Push policy data to OPA via the Data API."""
    from ansible_base.opa.client import _log_opa_interaction
    from ansible_base.opa.registry import opa_registry

    url = f"{opa_registry.server_url}/v1/data/dab_opa/user_policies"
    try:
        import time

        t0 = time.monotonic()
        resp = requests.put(url, json=user_policies, timeout=10)
        duration_ms = (time.monotonic() - t0) * 1000
        resp.raise_for_status()
        logger.info("Pushed policy data to OPA (%d users)", len(user_policies))
        _log_opa_interaction("PUT", url, user_policies, None, duration_ms, resp.status_code)
    except requests.RequestException:
        logger.exception("Failed to push policy data to OPA at %s", url)
