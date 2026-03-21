"""Tests for OPA permission classes and queryset filtering.

These tests verify that the OPA-based authorization system correctly:
- Filters querysets based on user permissions
- Grants/denies object-level access
- Handles superuser bypass
- Handles unauthenticated requests
"""

import pytest

from ansible_base.opa.permissions import OPAPermission, _get_action_for_request, _is_opa_resource
from ansible_base.opa.queryset import filter_queryset_for_user, user_can_access_obj
from ansible_base.opa.rego.sync import sync_to_opa
from test_app.models import Inventory, Organization


@pytest.mark.django_db
class TestQuerysetFiltering:
    """Test that OPA queryset filtering returns correct results."""

    def test_superuser_sees_all(self, admin_user, opa_inventory, opa_inventory2):
        qs = filter_queryset_for_user(Inventory.objects.all(), admin_user, "read")
        assert opa_inventory in qs
        assert opa_inventory2 in qs

    def test_unpermissioned_user_sees_nothing(self, opa_user, opa_inventory):
        sync_to_opa(debounce_seconds=0)
        qs = filter_queryset_for_user(Inventory.objects.all(), opa_user, "read")
        assert qs.count() == 0

    def test_user_sees_granted_inventory(self, opa_user, opa_inventory, opa_inventory2, grant_opa_role):
        grant_opa_role(
            opa_user,
            "test-inv-reader",
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

        qs = filter_queryset_for_user(Inventory.objects.all(), opa_user, "read")
        assert opa_inventory in qs
        assert opa_inventory2 not in qs

    def test_org_scoped_inventory_access(self, opa_user, opa_inventory, opa_inventory2, opa_org, grant_opa_role):
        grant_opa_role(
            opa_user,
            "test-org-inv-reader",
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

        qs = filter_queryset_for_user(Inventory.objects.all(), opa_user, "read")
        assert opa_inventory in qs
        assert opa_inventory2 not in qs

    def test_user_with_change_but_not_read(self, opa_user, opa_inventory, grant_opa_role):
        grant_opa_role(
            opa_user,
            "test-inv-changer",
            [
                {
                    "resource": "inventory",
                    "action": "change",
                    "field_name": "id",
                    "constant_value": str(opa_inventory.pk),
                },
            ],
        )
        sync_to_opa(debounce_seconds=0)

        read_qs = filter_queryset_for_user(Inventory.objects.all(), opa_user, "read")
        change_qs = filter_queryset_for_user(Inventory.objects.all(), opa_user, "change")
        assert opa_inventory not in read_qs
        assert opa_inventory in change_qs


@pytest.mark.django_db
class TestObjectAccess:
    """Test object-level permission checks."""

    def test_superuser_can_access(self, admin_user, opa_inventory):
        assert user_can_access_obj(admin_user, opa_inventory, "read")
        assert user_can_access_obj(admin_user, opa_inventory, "change")
        assert user_can_access_obj(admin_user, opa_inventory, "delete")

    def test_unpermissioned_user_cannot_access(self, opa_user, opa_inventory):
        sync_to_opa(debounce_seconds=0)
        assert not user_can_access_obj(opa_user, opa_inventory, "read")
        assert not user_can_access_obj(opa_user, opa_inventory, "change")

    def test_granted_user_can_access(self, opa_user, opa_inventory, grant_opa_role):
        grant_opa_role(
            opa_user,
            "test-inv-admin",
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

        assert user_can_access_obj(opa_user, opa_inventory, "read")
        assert user_can_access_obj(opa_user, opa_inventory, "change")
        assert not user_can_access_obj(opa_user, opa_inventory, "delete")


@pytest.mark.django_db
class TestOPAPermissionClass:
    """Test the OPAPermission DRF permission class."""

    def test_is_opa_resource_registered(self):
        assert _is_opa_resource(Inventory)
        assert _is_opa_resource(Organization)

    def test_is_opa_resource_unregistered(self):
        from test_app.models import Animal

        assert not _is_opa_resource(Animal)
