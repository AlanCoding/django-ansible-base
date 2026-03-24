"""Tests for tier 2 OPA evaluation: object access + related object permission checks.

Inventory has:
- organization FK (parent) — creating requires add_inventory on the org
- credential FK (related) — assigning requires use_credential on the credential
"""

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from ansible_base.lib.utils.response import get_relative_url
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


@pytest.fixture
def _opa_serializer_settings():
    """Monkeypatch InventorySerializer to use OPARelatedAccessMixin and views to use local OPA evaluation."""
    from rest_framework.permissions import IsAuthenticated

    from ansible_base.opa.evaluator import local_filter_queryset, local_user_can_access_obj
    from ansible_base.opa.mixins import OPARelatedAccessMixin
    from ansible_base.opa.registry import opa_registry
    from test_app import serializers
    from test_app.views import TestAppViewSet

    # Save originals
    old_bases = serializers.InventorySerializer.__bases__
    old_perms = TestAppViewSet.permission_classes
    old_filter = TestAppViewSet.filter_queryset

    # Replace RelatedAccessMixin with OPARelatedAccessMixin on InventorySerializer
    from ansible_base.rbac.api.related import RelatedAccessMixin

    new_bases = tuple(OPARelatedAccessMixin if b is RelatedAccessMixin else b for b in old_bases)
    serializers.InventorySerializer.__bases__ = new_bases

    # Custom permission class using local evaluator (no OPA HTTP dependency)
    from rest_framework.permissions import BasePermission

    class LocalOPAPermission(BasePermission):
        def has_permission(self, request, view):
            if not request.user or not request.user.is_authenticated:
                return False
            if request.user.is_superuser:
                return True
            if request.method == "POST" and getattr(view, "action", None) == "create":
                model_cls = view.get_queryset().model
                try:
                    resource_name = opa_registry.get_resource_name_for_model(model_cls)
                except ValueError:
                    return True
                from ansible_base.opa.evaluator import get_effective_policies

                return len(get_effective_policies(request.user, resource_name, "add")) > 0
            return True

        def has_object_permission(self, request, view, obj):
            if not request.user or not request.user.is_authenticated:
                return False
            if request.user.is_superuser:
                return True
            action_map = {"GET": "read", "HEAD": "read", "OPTIONS": "read",
                          "POST": "add", "PUT": "change", "PATCH": "change", "DELETE": "delete"}
            action = action_map.get(request.method, "read")
            return local_user_can_access_obj(request.user, obj, action)

    # Replace view permissions and filtering with local evaluator
    def opa_filter_queryset(view_self, qs):
        model_cls = qs.model
        try:
            opa_registry.get_resource_name_for_model(model_cls)
            qs = local_filter_queryset(qs, view_self.request.user, "read")
        except ValueError:
            pass
        qs = view_self.apply_optimizations(qs)
        from rest_framework.generics import GenericAPIView

        return GenericAPIView.filter_queryset(view_self, qs)

    TestAppViewSet.permission_classes = [IsAuthenticated, LocalOPAPermission]
    TestAppViewSet.filter_queryset = opa_filter_queryset

    yield

    # Restore
    serializers.InventorySerializer.__bases__ = old_bases
    TestAppViewSet.permission_classes = old_perms
    TestAppViewSet.filter_queryset = old_filter


@pytest.mark.django_db
@pytest.mark.usefixtures("_opa_serializer_settings")
class TestOPARelatedAccessMixinAPI:
    """Test OPARelatedAccessMixin through the DRF API."""

    def test_create_inventory_with_org_permission(self, related_user, related_org):
        """User with add_inventory on org can create inventory in that org."""
        _grant_opa_access(related_user, "inventory", "add", "organization_id", related_org.pk)
        client = APIClient()
        client.force_authenticate(user=related_user)

        r = client.post(
            get_relative_url("inventory-list"),
            data={"name": "New Inv", "organization": related_org.pk},
        )
        assert r.status_code == 201, r.data

    def test_create_inventory_without_org_permission(self, related_user, related_org, related_org2):
        """User without add_inventory on org2 cannot create inventory there."""
        # Grant add only on org1
        _grant_opa_access(related_user, "inventory", "add", "organization_id", related_org.pk)
        client = APIClient()
        client.force_authenticate(user=related_user)

        r = client.post(
            get_relative_url("inventory-list"),
            data={"name": "Bad Inv", "organization": related_org2.pk},
        )
        assert r.status_code == 403, r.data
        assert "organization" in r.data

    def test_update_credential_with_permission(self, related_user, related_inv, related_org, related_cred):
        """User with use_credential can assign credential to inventory."""
        _grant_opa_access(related_user, "inventory", "change", "id", related_inv.pk)
        _grant_opa_access(related_user, "inventory", "read", "id", related_inv.pk)
        _grant_opa_access(related_user, "credential", "use", "id", related_cred.pk)
        client = APIClient()
        client.force_authenticate(user=related_user)

        r = client.patch(
            get_relative_url("inventory-detail", kwargs={"pk": related_inv.pk}),
            data={"credential": related_cred.pk},
        )
        assert r.status_code == 200, r.data
        related_inv.refresh_from_db()
        assert related_inv.credential_id == related_cred.pk

    def test_update_credential_without_permission(self, related_user, related_inv, related_cred):
        """User without use_credential cannot assign credential to inventory."""
        _grant_opa_access(related_user, "inventory", "change", "id", related_inv.pk)
        _grant_opa_access(related_user, "inventory", "read", "id", related_inv.pk)
        # No use_credential granted
        client = APIClient()
        client.force_authenticate(user=related_user)

        r = client.patch(
            get_relative_url("inventory-detail", kwargs={"pk": related_inv.pk}),
            data={"credential": related_cred.pk},
        )
        assert r.status_code == 403, r.data
        assert "credential" in r.data

    def test_move_inventory_to_permitted_org(self, related_user, related_inv, related_org, related_org2):
        """User with add_inventory on both orgs can move inventory."""
        _grant_opa_access(related_user, "inventory", "change", "id", related_inv.pk)
        _grant_opa_access(related_user, "inventory", "read", "id", related_inv.pk)
        _grant_opa_access(related_user, "inventory", "add", "organization_id", related_org.pk)
        _grant_opa_access(related_user, "inventory", "add", "organization_id", related_org2.pk)
        client = APIClient()
        client.force_authenticate(user=related_user)

        r = client.patch(
            get_relative_url("inventory-detail", kwargs={"pk": related_inv.pk}),
            data={"organization": related_org2.pk},
        )
        assert r.status_code == 200, r.data

    def test_move_inventory_to_unpermitted_org(self, related_user, related_inv, related_org, related_org2):
        """User without add_inventory on org2 cannot move inventory there."""
        _grant_opa_access(related_user, "inventory", "change", "id", related_inv.pk)
        _grant_opa_access(related_user, "inventory", "read", "id", related_inv.pk)
        _grant_opa_access(related_user, "inventory", "add", "organization_id", related_org.pk)
        # No add on org2
        client = APIClient()
        client.force_authenticate(user=related_user)

        r = client.patch(
            get_relative_url("inventory-detail", kwargs={"pk": related_inv.pk}),
            data={"organization": related_org2.pk},
        )
        assert r.status_code == 403, r.data
        assert "organization" in r.data

    def test_unchanged_fk_not_checked(self, related_user, related_inv, related_org):
        """Updating non-FK fields doesn't trigger related checks."""
        _grant_opa_access(related_user, "inventory", "change", "id", related_inv.pk)
        _grant_opa_access(related_user, "inventory", "read", "id", related_inv.pk)
        # No add_inventory on org — but org isn't changing, so it shouldn't matter
        client = APIClient()
        client.force_authenticate(user=related_user)

        r = client.patch(
            get_relative_url("inventory-detail", kwargs={"pk": related_inv.pk}),
            data={"name": "Renamed Inv"},
        )
        assert r.status_code == 200, r.data

    def test_superuser_bypasses_related_checks_api(self, admin_user, related_inv, related_cred):
        """Superuser can assign any credential without use permission."""
        client = APIClient()
        client.force_authenticate(user=admin_user)

        r = client.patch(
            get_relative_url("inventory-detail", kwargs={"pk": related_inv.pk}),
            data={"credential": related_cred.pk},
        )
        assert r.status_code == 200, r.data

    def test_null_credential_allowed_without_permission(self, related_user, related_inv, related_org, related_cred):
        """User can clear a nullable non-parent FK without needing use permission."""
        related_inv.credential = related_cred
        related_inv.save()

        _grant_opa_access(related_user, "inventory", "change", "id", related_inv.pk)
        _grant_opa_access(related_user, "inventory", "read", "id", related_inv.pk)
        client = APIClient()
        client.force_authenticate(user=related_user)

        r = client.patch(
            get_relative_url("inventory-detail", kwargs={"pk": related_inv.pk}),
            data={"credential": None},
            format="json",
        )
        assert r.status_code == 200, r.data
        related_inv.refresh_from_db()
        assert related_inv.credential_id is None
