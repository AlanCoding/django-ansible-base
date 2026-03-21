"""Tests that verify OPA and local evaluator produce identical results."""

import pytest

from ansible_base.opa.evaluator import local_filter_queryset, local_user_can_access_obj
from ansible_base.opa.queryset import filter_queryset_for_user, user_can_access_obj
from ansible_base.opa.rego.sync import sync_to_opa
from test_app.models import Inventory, Organization


@pytest.mark.django_db
class TestEvaluatorParity:
    """Verify OPA and local evaluator return identical results."""

    def test_superuser_parity(self, admin_user, opa_inventory):
        opa_qs = filter_queryset_for_user(Inventory.objects.all(), admin_user, "read")
        local_qs = local_filter_queryset(Inventory.objects.all(), admin_user, "read")
        assert set(opa_qs.values_list("pk", flat=True)) == set(local_qs.values_list("pk", flat=True))

    def test_unpermissioned_parity(self, opa_user, opa_inventory):
        sync_to_opa(debounce_seconds=0)
        opa_qs = filter_queryset_for_user(Inventory.objects.all(), opa_user, "read")
        local_qs = local_filter_queryset(Inventory.objects.all(), opa_user, "read")
        assert set(opa_qs.values_list("pk", flat=True)) == set(local_qs.values_list("pk", flat=True))
        assert opa_qs.count() == 0

    def test_granted_parity(self, opa_user, opa_inventory, opa_inventory2, grant_opa_role):
        grant_opa_role(
            opa_user,
            "parity-test-inv-reader",
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

        opa_pks = set(filter_queryset_for_user(Inventory.objects.all(), opa_user, "read").values_list("pk", flat=True))
        local_pks = set(local_filter_queryset(Inventory.objects.all(), opa_user, "read").values_list("pk", flat=True))
        assert opa_pks == local_pks
        assert opa_inventory.pk in opa_pks
        assert opa_inventory2.pk not in opa_pks

    def test_org_scope_parity(self, opa_user, opa_inventory, opa_inventory2, opa_org, grant_opa_role):
        grant_opa_role(
            opa_user,
            "parity-test-org-reader",
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

        opa_pks = set(filter_queryset_for_user(Inventory.objects.all(), opa_user, "read").values_list("pk", flat=True))
        local_pks = set(local_filter_queryset(Inventory.objects.all(), opa_user, "read").values_list("pk", flat=True))
        assert opa_pks == local_pks

    def test_object_access_parity(self, opa_user, opa_inventory, grant_opa_role):
        grant_opa_role(
            opa_user,
            "parity-test-obj-access",
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

        for action in ("read", "change", "delete"):
            opa_result = user_can_access_obj(opa_user, opa_inventory, action)
            local_result = local_user_can_access_obj(opa_user, opa_inventory, action)
            assert opa_result == local_result, f"Mismatch on action '{action}': OPA={opa_result}, Local={local_result}"

    def test_multi_action_parity(self, opa_user, opa_inventory, opa_inventory2, opa_org, grant_opa_role):
        """Test parity across all actions with mixed scoping."""
        grant_opa_role(
            opa_user,
            "parity-multi-action",
            [
                {
                    "resource": "inventory",
                    "action": "read",
                    "field_name": "organization_id",
                    "constant_value": str(opa_org.pk),
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

        for action in ("read", "change", "delete", "add"):
            opa_pks = set(
                filter_queryset_for_user(Inventory.objects.all(), opa_user, action).values_list("pk", flat=True)
            )
            local_pks = set(
                local_filter_queryset(Inventory.objects.all(), opa_user, action).values_list("pk", flat=True)
            )
            assert opa_pks == local_pks, f"Mismatch on action '{action}': OPA={opa_pks}, Local={local_pks}"
