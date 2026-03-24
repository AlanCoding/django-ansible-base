"""Tests for tier 2 OPA evaluation: object access + related object permission checks.

Inventory has:
- organization FK (parent) — creating requires add_inventory on the org
- credential FK (related) — assigning requires use_credential on the credential
"""

import pytest
from django.contrib.auth import get_user_model

from ansible_base.opa.evaluator import (
    local_check_object,
    local_filter_queryset,
    local_user_can_access_obj,
)
from ansible_base.opa.models import GroupRoleAssignment, OPAGroup, Policy, Role
from test_app.models import Credential, Inventory, Organization

User = get_user_model()


@pytest.fixture
def related_org(db):
    return Organization.objects.create(name="Related Org")


@pytest.fixture
def related_org2(db):
    return Organization.objects.create(name="Other Org")


@pytest.fixture
def related_inv(related_org):
    return Inventory.objects.create(name="Related Inv", organization=related_org)


@pytest.fixture
def related_cred(related_org):
    return Credential.objects.create(name="Related Cred", organization=related_org)


@pytest.fixture
def related_user(db, local_authenticator):
    return User.objects.create_user(username="related_user", password="password")


def _grant_opa_access(user, resource, action, field_name, value):
    """Grant OPA access via role/policy/group."""
    group_name = f"user:{user.pk}"
    group, _ = OPAGroup.objects.get_or_create(name=group_name, defaults={"managed": True})
    group.users.add(user)
    role = Role.objects.create(name=f"test-{resource}-{action}-{user.pk}-{value}")
    Policy.objects.create(
        role=role,
        resource=resource,
        action=action,
        field_name=field_name,
        operator="eq",
        value_type="constant",
        constant_value=str(value),
    )
    GroupRoleAssignment.objects.create(group=group, role=role)


@pytest.mark.django_db
class TestTier2ObjectEvaluation:
    """Test tier 2: direct object attribute matching (no queryset)."""

    def test_object_access_by_id(self, related_user, related_inv):
        """User with id-scoped permission can access the specific object."""
        _grant_opa_access(related_user, "inventory", "change", "id", related_inv.pk)
        assert local_user_can_access_obj(related_user, related_inv, "change") is True

    def test_object_access_by_org(self, related_user, related_inv, related_org):
        """User with org-scoped permission can access objects in that org."""
        _grant_opa_access(related_user, "inventory", "read", "organization_id", related_org.pk)
        assert local_user_can_access_obj(related_user, related_inv, "read") is True

    def test_object_access_denied_wrong_org(self, related_user, related_inv, related_org2):
        """User with permission in org2 cannot access object in org1."""
        _grant_opa_access(related_user, "inventory", "read", "organization_id", related_org2.pk)
        assert local_user_can_access_obj(related_user, related_inv, "read") is False

    def test_object_access_denied_wrong_action(self, related_user, related_inv):
        """User with read permission cannot change the object."""
        _grant_opa_access(related_user, "inventory", "read", "id", related_inv.pk)
        assert local_user_can_access_obj(related_user, related_inv, "change") is False

    def test_superuser_always_allowed(self, related_inv, local_authenticator):
        """Superuser can access any object."""
        su = User.objects.create_user(username="su", password="password", is_superuser=True)
        assert local_user_can_access_obj(su, related_inv, "change") is True


@pytest.mark.django_db
class TestTier2RelatedObjectChecks:
    """Test tier 2 related object permission checks via local_check_object."""

    def test_related_org_check_allowed(self, related_user, related_inv, related_org):
        """User with add_inventory on org can set organization to that org."""
        _grant_opa_access(related_user, "inventory", "change", "id", related_inv.pk)
        _grant_opa_access(related_user, "inventory", "add", "organization_id", related_org.pk)

        result = local_check_object(
            related_user, related_inv, "change",
            related={"organization": {"resource": "inventory", "action": "add", "id": None, "org_id": related_org.pk}},
        )
        assert result["object_allowed"] is True
        assert result["related_denied"] == set()

    def test_related_org_check_denied(self, related_user, related_inv, related_org, related_org2):
        """User without add_inventory on org2 gets denied on organization field."""
        _grant_opa_access(related_user, "inventory", "change", "id", related_inv.pk)
        _grant_opa_access(related_user, "inventory", "add", "organization_id", related_org.pk)

        result = local_check_object(
            related_user, related_inv, "change",
            related={"organization": {"resource": "inventory", "action": "add", "id": None, "org_id": related_org2.pk}},
        )
        assert result["object_allowed"] is True
        assert "organization" in result["related_denied"]

    def test_related_credential_check_allowed(self, related_user, related_inv, related_cred):
        """User with use_credential on cred can assign it to inventory."""
        _grant_opa_access(related_user, "inventory", "change", "id", related_inv.pk)
        _grant_opa_access(related_user, "credential", "use", "id", related_cred.pk)

        result = local_check_object(
            related_user, related_inv, "change",
            related={"credential": {"resource": "credential", "action": "use", "id": related_cred.pk}},
        )
        assert result["object_allowed"] is True
        assert result["related_denied"] == set()

    def test_related_credential_check_denied(self, related_user, related_inv, related_cred):
        """User without use_credential gets denied on credential field."""
        _grant_opa_access(related_user, "inventory", "change", "id", related_inv.pk)
        # No use_credential granted

        result = local_check_object(
            related_user, related_inv, "change",
            related={"credential": {"resource": "credential", "action": "use", "id": related_cred.pk}},
        )
        assert result["object_allowed"] is True
        assert "credential" in result["related_denied"]

    def test_both_related_checks(self, related_user, related_inv, related_org, related_cred):
        """Both org and credential checks pass when user has both permissions."""
        _grant_opa_access(related_user, "inventory", "change", "id", related_inv.pk)
        _grant_opa_access(related_user, "inventory", "add", "organization_id", related_org.pk)
        _grant_opa_access(related_user, "credential", "use", "id", related_cred.pk)

        result = local_check_object(
            related_user, related_inv, "change",
            related={
                "organization": {"resource": "inventory", "action": "add", "id": None, "org_id": related_org.pk},
                "credential": {"resource": "credential", "action": "use", "id": related_cred.pk},
            },
        )
        assert result["object_allowed"] is True
        assert result["related_denied"] == set()

    def test_multiple_related_denials(self, related_user, related_inv, related_org2, related_cred):
        """Both org and credential checks fail when user has neither permission."""
        _grant_opa_access(related_user, "inventory", "change", "id", related_inv.pk)
        # No add on org2, no use on cred

        result = local_check_object(
            related_user, related_inv, "change",
            related={
                "organization": {"resource": "inventory", "action": "add", "id": None, "org_id": related_org2.pk},
                "credential": {"resource": "credential", "action": "use", "id": related_cred.pk},
            },
        )
        assert result["object_allowed"] is True
        assert "organization" in result["related_denied"]
        assert "credential" in result["related_denied"]

    def test_superuser_bypasses_related_checks(self, related_inv, related_cred, local_authenticator):
        """Superuser bypasses all related checks."""
        su = User.objects.create_user(username="su2", password="password", is_superuser=True)
        result = local_check_object(
            su, related_inv, "change",
            related={"credential": {"resource": "credential", "action": "use", "id": related_cred.pk}},
        )
        assert result["object_allowed"] is True
        assert result["related_denied"] == set()

    def test_object_denied_with_related_allowed(self, related_user, related_inv, related_cred):
        """Object access denied even if related checks would pass."""
        # No change permission on inventory, but has use on credential
        _grant_opa_access(related_user, "credential", "use", "id", related_cred.pk)

        result = local_check_object(
            related_user, related_inv, "change",
            related={"credential": {"resource": "credential", "action": "use", "id": related_cred.pk}},
        )
        assert result["object_allowed"] is False

    def test_queryset_filter_still_works(self, related_user, related_inv, related_org):
        """Tier 1 queryset filtering is unaffected by tier 2 changes."""
        _grant_opa_access(related_user, "inventory", "read", "organization_id", related_org.pk)
        qs = local_filter_queryset(Inventory.objects.all(), related_user, "read")
        assert related_inv.pk in set(qs.values_list("pk", flat=True))
