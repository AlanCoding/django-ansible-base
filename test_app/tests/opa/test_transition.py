"""Tests for the transition validation dual-evaluation mode (Phase 9)."""

import logging

import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings

from ansible_base.opa.evaluator import local_filter_queryset, local_user_can_access_obj
from ansible_base.opa.models import GroupRoleAssignment, OPAGroup, Policy, Role
from ansible_base.opa.transition import validate_object_access, validate_queryset_filter
from ansible_base.rbac.models import DABContentType, RoleDefinition
from test_app.models import Inventory, Organization

User = get_user_model()


@pytest.fixture
def transition_org(db):
    return Organization.objects.create(name="Transition Org")


@pytest.fixture
def transition_inv(transition_org):
    return Inventory.objects.create(name="Transition Inv", organization=transition_org)


@pytest.fixture
def transition_user(db, local_authenticator):
    return User.objects.create_user(username="transition_user", password="password")


def _grant_opa(user, org):
    """Grant OPA org-scoped read on inventory."""
    group_name = f"user:{user.pk}"
    group, _ = OPAGroup.objects.get_or_create(name=group_name, defaults={"managed": True})
    group.users.add(user)
    role = Role.objects.create(name=f"trans-role-{user.pk}-{org.pk}")
    Policy.objects.create(
        role=role,
        resource="inventory",
        action="read",
        field_name="organization_id",
        operator="eq",
        value_type="constant",
        constant_value=str(org.pk),
    )
    GroupRoleAssignment.objects.create(group=group, role=role)


def _grant_rbac(user, inv):
    """Grant RBAC view_inventory on a specific inventory."""
    inv_ct = DABContentType.objects.get_for_model(Inventory)
    rd, _ = RoleDefinition.objects.get_or_create(
        name="Trans Inv Viewer",
        permissions=["view_inventory"],
        defaults={"content_type": inv_ct},
    )
    rd.give_permission(user, inv)


@pytest.mark.django_db
class TestTransitionValidation:
    @override_settings(DAB_OPA_TRANSITION_VALIDATION=False)
    def test_disabled_no_comparison(self, transition_org, transition_inv, transition_user):
        """When disabled, validate functions are no-ops."""
        qs = Inventory.objects.all()
        result = validate_queryset_filter(qs, transition_user, "read")
        # Should return the same queryset unchanged
        assert list(result) == list(qs)

    @override_settings(DAB_OPA_TRANSITION_VALIDATION=True)
    def test_matching_results_logged_debug(self, transition_org, transition_inv, transition_user, caplog):
        """When OPA and RBAC agree, log at DEBUG level."""
        # Grant both OPA and RBAC the same access
        _grant_opa(transition_user, transition_org)
        _grant_rbac(transition_user, transition_inv)

        opa_qs = local_filter_queryset(Inventory.objects.all(), transition_user, "read")

        with caplog.at_level(logging.DEBUG, logger="ansible_base.opa.transition"):
            validate_queryset_filter(opa_qs, transition_user, "read")

        assert any("TRANSITION MATCH queryset" in r.message for r in caplog.records)

    @override_settings(DAB_OPA_TRANSITION_VALIDATION=True)
    def test_mismatch_logged_error(self, transition_org, transition_inv, transition_user, caplog):
        """When OPA and RBAC disagree, log at ERROR level."""
        # Grant OPA but NOT RBAC
        _grant_opa(transition_user, transition_org)

        opa_qs = local_filter_queryset(Inventory.objects.all(), transition_user, "read")

        with caplog.at_level(logging.DEBUG, logger="ansible_base.opa.transition"):
            validate_queryset_filter(opa_qs, transition_user, "read")

        assert any("TRANSITION MISMATCH queryset" in r.message for r in caplog.records)

    @override_settings(DAB_OPA_TRANSITION_VALIDATION=True)
    def test_object_access_match(self, transition_org, transition_inv, transition_user, caplog):
        """Object access match logs at DEBUG."""
        _grant_opa(transition_user, transition_org)
        _grant_rbac(transition_user, transition_inv)

        opa_result = local_user_can_access_obj(transition_user, transition_inv, "read")

        with caplog.at_level(logging.DEBUG, logger="ansible_base.opa.transition"):
            validate_object_access(opa_result, transition_user, transition_inv, "read")

        assert any("TRANSITION MATCH object" in r.message for r in caplog.records)

    @override_settings(DAB_OPA_TRANSITION_VALIDATION=True)
    def test_object_access_mismatch(self, transition_org, transition_inv, transition_user, caplog):
        """Object access mismatch logs at ERROR."""
        # OPA grants, RBAC does not
        _grant_opa(transition_user, transition_org)

        with caplog.at_level(logging.DEBUG, logger="ansible_base.opa.transition"):
            validate_object_access(True, transition_user, transition_inv, "read")

        assert any("TRANSITION MISMATCH object" in r.message for r in caplog.records)

    @override_settings(DAB_OPA_TRANSITION_VALIDATION=True)
    def test_opa_result_is_authoritative(self, transition_org, transition_inv, transition_user):
        """Even on mismatch, the OPA result is returned, not the RBAC result."""
        # OPA grants, RBAC does not
        _grant_opa(transition_user, transition_org)

        opa_qs = local_filter_queryset(Inventory.objects.all(), transition_user, "read")
        result = validate_queryset_filter(opa_qs, transition_user, "read")

        # OPA granted access — result should still include the inventory
        assert transition_inv.pk in set(result.values_list("pk", flat=True))

    @override_settings(DAB_OPA_TRANSITION_VALIDATION=True)
    def test_unregistered_model_skipped(self, transition_user, caplog):
        """Models not in RBAC registry are silently skipped."""
        # OPAGroup is not RBAC-registered, so transition check should be a no-op
        from ansible_base.opa.models import OPAGroup as OPAGroupModel

        qs = OPAGroupModel.objects.all()
        with caplog.at_level(logging.DEBUG, logger="ansible_base.opa.transition"):
            result = validate_queryset_filter(qs, transition_user, "read")

        assert list(result) == list(qs)
        assert not any("TRANSITION" in r.message for r in caplog.records)

    @override_settings(DAB_OPA_TRANSITION_VALIDATION=True)
    def test_superuser_bypasses_both(self, admin_user, transition_inv):
        """Superusers bypass OPA entirely — no transition check needed."""
        opa_qs = local_filter_queryset(Inventory.objects.all(), admin_user, "read")
        # Superuser gets unfiltered queryset, transition validation won't be called
        # because filter_queryset_for_user returns early for superusers
        assert transition_inv.pk in set(opa_qs.values_list("pk", flat=True))
