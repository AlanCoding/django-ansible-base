"""API integration tests for OPA-based authorization.

These tests verify that the OPA permission system works end-to-end
through the DRF API, including queryset filtering and object-level checks.

Tests require OPA to be running (make opa).
"""

import pytest

from ansible_base.lib.utils.response import get_relative_url
from ansible_base.opa.rego.sync import sync_to_opa


@pytest.fixture(autouse=True)
def _opa_rest_settings(settings):
    """Override DRF permission classes and queryset filtering to use OPA instead of RBAC.

    DRF resolves DEFAULT_PERMISSION_CLASSES at class definition time, so we
    must monkeypatch view classes directly.
    """
    from rest_framework.permissions import IsAuthenticated

    from ansible_base.opa.permissions import OPAPermission
    from ansible_base.opa.queryset import filter_queryset_for_user
    from ansible_base.opa.registry import opa_registry
    from test_app.views import TestAppViewSet

    old_perms = TestAppViewSet.permission_classes
    old_filter = TestAppViewSet.filter_queryset

    def opa_filter_queryset(view_self, qs):
        model_cls = qs.model
        try:
            opa_registry.get_resource_name_for_model(model_cls)
            qs = filter_queryset_for_user(qs, view_self.request.user, "read")
        except ValueError:
            pass
        qs = view_self.apply_optimizations(qs)
        # Call GenericAPIView.filter_queryset (skip TestAppViewSet's RBAC filtering)
        from rest_framework.generics import GenericAPIView

        return GenericAPIView.filter_queryset(view_self, qs)

    TestAppViewSet.permission_classes = [IsAuthenticated, OPAPermission]
    TestAppViewSet.filter_queryset = opa_filter_queryset
    yield
    TestAppViewSet.permission_classes = old_perms
    TestAppViewSet.filter_queryset = old_filter


@pytest.mark.django_db
class TestInventoryAPIAccess:
    """Test inventory API access through OPA."""

    def test_superuser_sees_all_inventories(self, admin_api_client, opa_inventory, opa_inventory2):
        r = admin_api_client.get(get_relative_url("inventory-list"))
        assert r.status_code == 200
        pks = [item["id"] for item in r.data["results"]]
        assert opa_inventory.pk in pks
        assert opa_inventory2.pk in pks

    def test_unpermissioned_user_sees_no_inventories(self, opa_user_client, opa_inventory):
        sync_to_opa(debounce_seconds=0)
        r = opa_user_client.get(get_relative_url("inventory-list"))
        assert r.status_code == 200
        assert r.data["count"] == 0

    def test_user_sees_granted_inventory_only(
        self, opa_user_client, opa_user, opa_inventory, opa_inventory2, grant_opa_role
    ):
        grant_opa_role(
            opa_user,
            "api-test-inv-reader",
            [
                {
                    "resource": "inventory",
                    "action": "read",
                    "field_name": "id",
                    "constant_value": str(opa_inventory.pk),
                },
            ],
        )
        sync_to_opa(debounce_seconds=0)

        r = opa_user_client.get(get_relative_url("inventory-list"))
        assert r.status_code == 200
        pks = [item["id"] for item in r.data["results"]]
        assert opa_inventory.pk in pks
        assert opa_inventory2.pk not in pks

    def test_user_can_read_granted_inventory_detail(
        self, opa_user_client, opa_user, opa_inventory, grant_opa_role
    ):
        grant_opa_role(
            opa_user,
            "api-test-inv-detail-reader",
            [
                {
                    "resource": "inventory",
                    "action": "read",
                    "field_name": "id",
                    "constant_value": str(opa_inventory.pk),
                },
            ],
        )
        sync_to_opa(debounce_seconds=0)

        url = get_relative_url("inventory-detail", kwargs={"pk": opa_inventory.pk})
        r = opa_user_client.get(url)
        assert r.status_code == 200
        assert r.data["name"] == opa_inventory.name

    def test_user_cannot_read_ungranted_inventory_detail(
        self, opa_user_client, opa_user, opa_inventory
    ):
        sync_to_opa(debounce_seconds=0)
        url = get_relative_url("inventory-detail", kwargs={"pk": opa_inventory.pk})
        r = opa_user_client.get(url)
        assert r.status_code == 404

    def test_user_can_patch_with_change_permission(
        self, opa_user_client, opa_user, opa_inventory, grant_opa_role
    ):
        grant_opa_role(
            opa_user,
            "api-test-inv-editor",
            [
                {
                    "resource": "inventory",
                    "action": "read",
                    "field_name": "id",
                    "constant_value": str(opa_inventory.pk),
                },
                {
                    "resource": "inventory",
                    "action": "change",
                    "field_name": "id",
                    "constant_value": str(opa_inventory.pk),
                },
            ],
        )
        sync_to_opa(debounce_seconds=0)

        url = get_relative_url("inventory-detail", kwargs={"pk": opa_inventory.pk})
        r = opa_user_client.patch(url, {"name": "Updated Name"}, format="json")
        assert r.status_code == 200
        assert r.data["name"] == "Updated Name"

    def test_user_cannot_patch_without_change_permission(
        self, opa_user_client, opa_user, opa_inventory, grant_opa_role
    ):
        # Grant read only
        grant_opa_role(
            opa_user,
            "api-test-inv-readonly",
            [
                {
                    "resource": "inventory",
                    "action": "read",
                    "field_name": "id",
                    "constant_value": str(opa_inventory.pk),
                },
            ],
        )
        sync_to_opa(debounce_seconds=0)

        url = get_relative_url("inventory-detail", kwargs={"pk": opa_inventory.pk})
        r = opa_user_client.patch(url, {"name": "Should Fail"}, format="json")
        assert r.status_code == 403

    def test_user_cannot_delete_without_delete_permission(
        self, opa_user_client, opa_user, opa_inventory, grant_opa_role
    ):
        # Grant read + change but NOT delete
        grant_opa_role(
            opa_user,
            "api-test-inv-no-delete",
            [
                {
                    "resource": "inventory",
                    "action": "read",
                    "field_name": "id",
                    "constant_value": str(opa_inventory.pk),
                },
                {
                    "resource": "inventory",
                    "action": "change",
                    "field_name": "id",
                    "constant_value": str(opa_inventory.pk),
                },
            ],
        )
        sync_to_opa(debounce_seconds=0)

        url = get_relative_url("inventory-detail", kwargs={"pk": opa_inventory.pk})
        r = opa_user_client.delete(url)
        assert r.status_code == 403

    def test_org_scoped_access(
        self, opa_user_client, opa_user, opa_inventory, opa_inventory2, opa_org, grant_opa_role
    ):
        """Grant read access to all inventories in an org."""
        grant_opa_role(
            opa_user,
            "api-test-org-inv-reader",
            [
                {
                    "resource": "inventory",
                    "action": "read",
                    "field_name": "organization_id",
                    "constant_value": str(opa_org.pk),
                },
            ],
        )
        sync_to_opa(debounce_seconds=0)

        r = opa_user_client.get(get_relative_url("inventory-list"))
        assert r.status_code == 200
        pks = [item["id"] for item in r.data["results"]]
        assert opa_inventory.pk in pks
        assert opa_inventory2.pk not in pks


@pytest.mark.django_db
class TestOrganizationAPIAccess:
    """Test organization API access through OPA."""

    def test_superuser_sees_all_orgs(self, admin_api_client, opa_org, opa_org2):
        r = admin_api_client.get(get_relative_url("organization-list"))
        assert r.status_code == 200
        pks = [item["id"] for item in r.data["results"]]
        assert opa_org.pk in pks
        assert opa_org2.pk in pks

    def test_unpermissioned_user_sees_no_orgs(self, opa_user_client, opa_org):
        sync_to_opa(debounce_seconds=0)
        r = opa_user_client.get(get_relative_url("organization-list"))
        assert r.status_code == 200
        assert r.data["count"] == 0

    def test_user_sees_granted_org(self, opa_user_client, opa_user, opa_org, opa_org2, grant_opa_role):
        grant_opa_role(
            opa_user,
            "api-test-org-reader",
            [
                {
                    "resource": "organization",
                    "action": "read",
                    "field_name": "id",
                    "constant_value": str(opa_org.pk),
                },
            ],
        )
        sync_to_opa(debounce_seconds=0)

        r = opa_user_client.get(get_relative_url("organization-list"))
        assert r.status_code == 200
        pks = [item["id"] for item in r.data["results"]]
        assert opa_org.pk in pks
        assert opa_org2.pk not in pks


@pytest.mark.django_db
class TestUnauthenticatedAccess:
    """Test that unauthenticated requests are denied."""

    def test_unauthenticated_list(self, unauthenticated_api_client, opa_inventory):
        r = unauthenticated_api_client.get(get_relative_url("inventory-list"))
        assert r.status_code in (401, 403)

    def test_unauthenticated_detail(self, unauthenticated_api_client, opa_inventory):
        url = get_relative_url("inventory-detail", kwargs={"pk": opa_inventory.pk})
        r = unauthenticated_api_client.get(url)
        assert r.status_code in (401, 403)


@pytest.mark.django_db
class TestMultipleUsers:
    """Test that different users see different results."""

    def test_two_users_different_access(
        self,
        opa_user_client,
        opa_user2_client,
        opa_user,
        opa_user2,
        opa_inventory,
        opa_inventory2,
        grant_opa_role,
    ):
        # User 1 can see inventory 1
        grant_opa_role(
            opa_user,
            "api-test-user1-inv",
            [
                {
                    "resource": "inventory",
                    "action": "read",
                    "field_name": "id",
                    "constant_value": str(opa_inventory.pk),
                },
            ],
        )
        # User 2 can see inventory 2
        grant_opa_role(
            opa_user2,
            "api-test-user2-inv",
            [
                {
                    "resource": "inventory",
                    "action": "read",
                    "field_name": "id",
                    "constant_value": str(opa_inventory2.pk),
                },
            ],
        )
        sync_to_opa(debounce_seconds=0)

        r1 = opa_user_client.get(get_relative_url("inventory-list"))
        r2 = opa_user2_client.get(get_relative_url("inventory-list"))

        pks1 = [item["id"] for item in r1.data["results"]]
        pks2 = [item["id"] for item in r2.data["results"]]

        assert opa_inventory.pk in pks1
        assert opa_inventory2.pk not in pks1

        assert opa_inventory2.pk in pks2
        assert opa_inventory.pk not in pks2
