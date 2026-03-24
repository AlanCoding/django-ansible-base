import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from ansible_base.opa.models import GroupRoleAssignment, OPAGroup, Policy, Role
from test_app.models import InstanceGroup, Inventory, Organization, Team

User = get_user_model()


@pytest.fixture
def opa_org(db):
    return Organization.objects.create(name="OPA Test Org")


@pytest.fixture
def opa_org2(db):
    return Organization.objects.create(name="OPA Test Org 2")


@pytest.fixture
def opa_inventory(opa_org):
    return Inventory.objects.create(name="OPA Test Inventory", organization=opa_org)


@pytest.fixture
def opa_inventory2(opa_org2):
    return Inventory.objects.create(name="OPA Test Inventory 2", organization=opa_org2)


@pytest.fixture
def opa_team(opa_org):
    return Team.objects.create(name="OPA Test Team", organization=opa_org)


@pytest.fixture
def opa_instance_group(db):
    return InstanceGroup.objects.create(name="OPA Test IG")


@pytest.fixture
def opa_user(db, local_authenticator):
    return User.objects.create_user(username="opa_user", password="password")


@pytest.fixture
def opa_user2(db, local_authenticator):
    return User.objects.create_user(username="opa_user2", password="password")


@pytest.fixture
def opa_user_client(opa_user):
    client = APIClient()
    client.login(username="opa_user", password="password")
    yield client
    try:
        client.logout()
    except AttributeError:
        pass


@pytest.fixture
def opa_user2_client(opa_user2):
    client = APIClient()
    client.login(username="opa_user2", password="password")
    yield client
    try:
        client.logout()
    except AttributeError:
        pass


def _ensure_user_group(user):
    """Ensure a per-user OPAGroup exists."""
    group_name = f"user:{user.pk}"
    group, _ = OPAGroup.objects.get_or_create(name=group_name, defaults={"managed": True})
    group.users.add(user)
    return group


def _grant_opa_role(user, role_name, policies):
    """Create a role with policies and assign it to a user's OPA group.

    Args:
        user: The user to grant the role to
        role_name: Unique name for the role
        policies: List of dicts with keys: resource, action, field_name, operator, value_type, constant_value
    """
    group = _ensure_user_group(user)
    role, _ = Role.objects.get_or_create(name=role_name, defaults={"managed": True})
    for p in policies:
        Policy.objects.get_or_create(
            role=role,
            resource=p["resource"],
            action=p["action"],
            field_name=p["field_name"],
            operator=p.get("operator", "eq"),
            value_type=p.get("value_type", "constant"),
            defaults={"constant_value": p.get("constant_value")},
        )
    GroupRoleAssignment.objects.get_or_create(group=group, role=role)
    return role


@pytest.fixture
def grant_opa_role():
    """Fixture that returns a helper to grant OPA roles."""
    return _grant_opa_role


@pytest.fixture
def sync_policies():
    """Fixture that syncs policy definitions to OPA. Call after creating policies."""

    def _sync():
        from ansible_base.opa.rego.sync import sync_policies_to_opa

        sync_policies_to_opa()

    return _sync
