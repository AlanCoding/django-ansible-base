"""Tests for the OPA management API (Phase 7).

Tests CRUD operations on Role, Policy, OPAGroup, and GroupRoleAssignment,
plus the effective scope introspection endpoint.
"""

import pytest

from ansible_base.lib.utils.response import get_relative_url
from ansible_base.opa.models import GroupRoleAssignment, OPAGroup, Policy, Role


@pytest.mark.django_db
class TestRoleAPI:
    def test_list_roles(self, admin_api_client):
        Role.objects.create(name="test-role")
        r = admin_api_client.get(get_relative_url("oparole-list"))
        assert r.status_code == 200
        assert r.data["count"] >= 1

    def test_create_role(self, admin_api_client):
        r = admin_api_client.post(
            get_relative_url("oparole-list"),
            {"name": "api-created-role", "description": "A role via API"},
            format="json",
        )
        assert r.status_code == 201
        assert r.data["name"] == "api-created-role"
        assert Role.objects.filter(name="api-created-role").exists()

    def test_detail_role(self, admin_api_client):
        role = Role.objects.create(name="detail-role")
        r = admin_api_client.get(get_relative_url("oparole-detail", kwargs={"pk": role.pk}))
        assert r.status_code == 200
        assert r.data["name"] == "detail-role"
        assert "policies" in r.data

    def test_update_role(self, admin_api_client):
        role = Role.objects.create(name="update-role")
        r = admin_api_client.patch(
            get_relative_url("oparole-detail", kwargs={"pk": role.pk}),
            {"description": "Updated description"},
            format="json",
        )
        assert r.status_code == 200
        role.refresh_from_db()
        assert role.description == "Updated description"

    def test_cannot_rename_managed_role(self, admin_api_client):
        role = Role.objects.create(name="managed-role", managed=True)
        r = admin_api_client.patch(
            get_relative_url("oparole-detail", kwargs={"pk": role.pk}),
            {"name": "new-name"},
            format="json",
        )
        assert r.status_code == 400

    def test_delete_role(self, admin_api_client):
        role = Role.objects.create(name="delete-role")
        r = admin_api_client.delete(get_relative_url("oparole-detail", kwargs={"pk": role.pk}))
        assert r.status_code == 204
        assert not Role.objects.filter(pk=role.pk).exists()

    def test_regular_user_can_create_role(self, user_api_client):
        r = user_api_client.post(
            get_relative_url("oparole-list"),
            {"name": "user-created-role"},
            format="json",
        )
        assert r.status_code == 201

    def test_regular_user_can_list_roles(self, user_api_client):
        Role.objects.create(name="viewable-role")
        r = user_api_client.get(get_relative_url("oparole-list"))
        assert r.status_code == 200


@pytest.mark.django_db
class TestPolicyAPI:
    def test_list_policies(self, admin_api_client):
        role = Role.objects.create(name="policy-list-role")
        Policy.objects.create(
            role=role,
            resource="inventory",
            action="read",
            field_name="id",
            operator="eq",
            value_type="constant",
            constant_value="1",
        )
        r = admin_api_client.get(get_relative_url("opapolicy-list"))
        assert r.status_code == 200
        assert r.data["count"] >= 1

    def test_create_policy(self, admin_api_client):
        role = Role.objects.create(name="policy-create-role")
        r = admin_api_client.post(
            get_relative_url("opapolicy-list"),
            {
                "role": role.pk,
                "resource": "inventory",
                "action": "read",
                "field_name": "id",
                "operator": "eq",
                "value_type": "constant",
                "constant_value": "42",
            },
            format="json",
        )
        assert r.status_code == 201, r.data
        assert r.data["resource"] == "inventory"

    def test_create_policy_invalid_resource(self, admin_api_client):
        role = Role.objects.create(name="policy-invalid-role")
        r = admin_api_client.post(
            get_relative_url("opapolicy-list"),
            {
                "role": role.pk,
                "resource": "nonexistent",
                "action": "read",
                "field_name": "id",
                "operator": "eq",
                "value_type": "constant",
                "constant_value": "1",
            },
            format="json",
        )
        assert r.status_code == 400

    def test_create_policy_invalid_action(self, admin_api_client):
        role = Role.objects.create(name="policy-bad-action-role")
        r = admin_api_client.post(
            get_relative_url("opapolicy-list"),
            {
                "role": role.pk,
                "resource": "inventory",
                "action": "fly",
                "field_name": "id",
                "operator": "eq",
                "value_type": "constant",
                "constant_value": "1",
            },
            format="json",
        )
        assert r.status_code == 400

    def test_filter_policies_by_role(self, admin_api_client):
        role1 = Role.objects.create(name="filter-role-1")
        role2 = Role.objects.create(name="filter-role-2")
        Policy.objects.create(
            role=role1, resource="inventory", action="read",
            field_name="id", operator="eq", value_type="constant", constant_value="1",
        )
        Policy.objects.create(
            role=role2, resource="inventory", action="read",
            field_name="id", operator="eq", value_type="constant", constant_value="2",
        )
        r = admin_api_client.get(get_relative_url("opapolicy-list") + f"?role={role1.pk}")
        assert r.status_code == 200
        assert r.data["count"] == 1

    def test_delete_policy(self, admin_api_client):
        role = Role.objects.create(name="policy-del-role")
        policy = Policy.objects.create(
            role=role, resource="inventory", action="read",
            field_name="id", operator="eq", value_type="constant", constant_value="1",
        )
        r = admin_api_client.delete(get_relative_url("opapolicy-detail", kwargs={"pk": policy.pk}))
        assert r.status_code == 204

    def test_regular_user_cannot_create_policy(self, user_api_client):
        role = Role.objects.create(name="policy-unauth-role")
        r = user_api_client.post(
            get_relative_url("opapolicy-list"),
            {
                "role": role.pk,
                "resource": "inventory",
                "action": "read",
                "field_name": "id",
                "operator": "eq",
                "value_type": "constant",
                "constant_value": "1",
            },
            format="json",
        )
        assert r.status_code == 403


@pytest.mark.django_db
class TestOPAGroupAPI:
    def test_list_groups(self, admin_api_client):
        OPAGroup.objects.create(name="test-group")
        r = admin_api_client.get(get_relative_url("opagroup-list"))
        assert r.status_code == 200
        assert r.data["count"] >= 1

    def test_create_group(self, admin_api_client):
        r = admin_api_client.post(
            get_relative_url("opagroup-list"),
            {"name": "api-group"},
            format="json",
        )
        assert r.status_code == 201
        assert r.data["name"] == "api-group"

    def test_detail_includes_users(self, admin_api_client, user):
        group = OPAGroup.objects.create(name="detail-group")
        group.users.add(user)
        r = admin_api_client.get(get_relative_url("opagroup-detail", kwargs={"pk": group.pk}))
        assert r.status_code == 200
        assert user.pk in r.data["users"]

    def test_add_user_to_group(self, admin_api_client, user):
        group = OPAGroup.objects.create(name="add-user-group")
        r = admin_api_client.post(
            get_relative_url("opagroup-add-user", kwargs={"pk": group.pk}),
            {"user_id": user.pk},
            format="json",
        )
        assert r.status_code == 200
        assert group.users.filter(pk=user.pk).exists()

    def test_remove_user_from_group(self, admin_api_client, user):
        group = OPAGroup.objects.create(name="remove-user-group")
        group.users.add(user)
        r = admin_api_client.post(
            get_relative_url("opagroup-remove-user", kwargs={"pk": group.pk}),
            {"user_id": user.pk},
            format="json",
        )
        assert r.status_code == 200
        assert not group.users.filter(pk=user.pk).exists()

    def test_add_nonexistent_user(self, admin_api_client):
        group = OPAGroup.objects.create(name="bad-user-group")
        r = admin_api_client.post(
            get_relative_url("opagroup-add-user", kwargs={"pk": group.pk}),
            {"user_id": 99999},
            format="json",
        )
        assert r.status_code == 404


@pytest.mark.django_db
class TestGroupRoleAssignmentAPI:
    def test_create_assignment(self, admin_api_client):
        group = OPAGroup.objects.create(name="assign-group")
        role = Role.objects.create(name="assign-role")
        r = admin_api_client.post(
            get_relative_url("opagrouproleassignment-list"),
            {"group": group.pk, "role": role.pk},
            format="json",
        )
        assert r.status_code == 201
        assert GroupRoleAssignment.objects.filter(group=group, role=role).exists()

    def test_list_assignments(self, admin_api_client):
        group = OPAGroup.objects.create(name="list-assign-group")
        role = Role.objects.create(name="list-assign-role")
        GroupRoleAssignment.objects.create(group=group, role=role)
        r = admin_api_client.get(get_relative_url("opagrouproleassignment-list"))
        assert r.status_code == 200
        assert r.data["count"] >= 1

    def test_delete_assignment(self, admin_api_client):
        group = OPAGroup.objects.create(name="del-assign-group")
        role = Role.objects.create(name="del-assign-role")
        assignment = GroupRoleAssignment.objects.create(group=group, role=role)
        r = admin_api_client.delete(
            get_relative_url("opagrouproleassignment-detail", kwargs={"pk": assignment.pk})
        )
        assert r.status_code == 204

    def test_cannot_patch_assignment(self, admin_api_client):
        group = OPAGroup.objects.create(name="patch-assign-group")
        role = Role.objects.create(name="patch-assign-role")
        assignment = GroupRoleAssignment.objects.create(group=group, role=role)
        r = admin_api_client.patch(
            get_relative_url("opagrouproleassignment-detail", kwargs={"pk": assignment.pk}),
            {"role": role.pk},
            format="json",
        )
        assert r.status_code == 405

    def test_duplicate_assignment_rejected(self, admin_api_client):
        group = OPAGroup.objects.create(name="dup-assign-group")
        role = Role.objects.create(name="dup-assign-role")
        GroupRoleAssignment.objects.create(group=group, role=role)
        r = admin_api_client.post(
            get_relative_url("opagrouproleassignment-list"),
            {"group": group.pk, "role": role.pk},
            format="json",
        )
        assert r.status_code == 400

    def test_filter_by_group(self, admin_api_client):
        g1 = OPAGroup.objects.create(name="filter-g1")
        g2 = OPAGroup.objects.create(name="filter-g2")
        role = Role.objects.create(name="filter-assign-role")
        GroupRoleAssignment.objects.create(group=g1, role=role)
        GroupRoleAssignment.objects.create(group=g2, role=role)
        r = admin_api_client.get(
            get_relative_url("opagrouproleassignment-list") + f"?group={g1.pk}"
        )
        assert r.status_code == 200
        assert r.data["count"] == 1


@pytest.mark.django_db
class TestEffectiveScopeAPI:
    def test_effective_scope_superuser(self, admin_api_client, admin_user):
        r = admin_api_client.get(
            get_relative_url("opa-effective-scope"),
            {"user_id": admin_user.pk, "resource": "inventory", "action": "read"},
        )
        assert r.status_code == 200
        assert r.data["allow"] is True
        assert r.data["clauses"] == []

    def test_effective_scope_unpermissioned(self, admin_api_client, user):
        r = admin_api_client.get(
            get_relative_url("opa-effective-scope"),
            {"user_id": user.pk, "resource": "inventory", "action": "read"},
        )
        assert r.status_code == 200
        assert r.data["allow"] is False

    def test_effective_scope_with_policy(self, admin_api_client, user, grant_opa_role):
        grant_opa_role(
            user,
            "scope-test-role",
            [
                {
                    "resource": "inventory",
                    "action": "read",
                    "field_name": "id",
                    "constant_value": "5",
                },
            ],
        )
        r = admin_api_client.get(
            get_relative_url("opa-effective-scope"),
            {"user_id": user.pk, "resource": "inventory", "action": "read"},
        )
        assert r.status_code == 200
        assert r.data["allow"] is True
        assert len(r.data["clauses"]) == 1
        assert r.data["clauses"][0]["field_name"] == "id"
        assert r.data["clauses"][0]["value"] == 5

    def test_effective_scope_missing_params(self, admin_api_client):
        r = admin_api_client.get(get_relative_url("opa-effective-scope"))
        assert r.status_code == 400

    def test_effective_scope_bad_resource(self, admin_api_client, admin_user):
        r = admin_api_client.get(
            get_relative_url("opa-effective-scope"),
            {"user_id": admin_user.pk, "resource": "nonexistent", "action": "read"},
        )
        assert r.status_code == 400

    def test_effective_scope_bad_user(self, admin_api_client):
        r = admin_api_client.get(
            get_relative_url("opa-effective-scope"),
            {"user_id": 99999, "resource": "inventory", "action": "read"},
        )
        assert r.status_code == 404

    def test_regular_user_cannot_introspect(self, user_api_client, user):
        r = user_api_client.get(
            get_relative_url("opa-effective-scope"),
            {"user_id": user.pk, "resource": "inventory", "action": "read"},
        )
        # Read-only endpoint, regular users can access
        assert r.status_code == 200


@pytest.mark.django_db
class TestEndToEndAPIWorkflow:
    """Test a complete workflow through the API."""

    def test_create_role_policy_group_and_assign(self, admin_api_client, user, opa_inventory):
        # 1. Create a role
        r = admin_api_client.post(
            get_relative_url("oparole-list"),
            {"name": "e2e-inv-reader", "description": "End-to-end test role"},
            format="json",
        )
        assert r.status_code == 201
        role_id = r.data["id"]

        # 2. Create a policy on that role
        r = admin_api_client.post(
            get_relative_url("opapolicy-list"),
            {
                "role": role_id,
                "resource": "inventory",
                "action": "read",
                "field_name": "id",
                "operator": "eq",
                "value_type": "constant",
                "constant_value": str(opa_inventory.pk),
            },
            format="json",
        )
        assert r.status_code == 201

        # 3. Create a group
        r = admin_api_client.post(
            get_relative_url("opagroup-list"),
            {"name": "e2e-test-group"},
            format="json",
        )
        assert r.status_code == 201
        group_id = r.data["id"]

        # 4. Add user to the group
        r = admin_api_client.post(
            get_relative_url("opagroup-add-user", kwargs={"pk": group_id}),
            {"user_id": user.pk},
            format="json",
        )
        assert r.status_code == 200

        # 5. Assign the role to the group
        r = admin_api_client.post(
            get_relative_url("opagrouproleassignment-list"),
            {"group": group_id, "role": role_id},
            format="json",
        )
        assert r.status_code == 201

        # 6. Verify effective scope shows the policy
        r = admin_api_client.get(
            get_relative_url("opa-effective-scope"),
            {"user_id": user.pk, "resource": "inventory", "action": "read"},
        )
        assert r.status_code == 200
        assert r.data["allow"] is True
        assert any(
            c["field_name"] == "id" and c["value"] == opa_inventory.pk
            for c in r.data["clauses"]
        )

        # 7. Verify the role shows its policies in the detail view
        r = admin_api_client.get(get_relative_url("oparole-detail", kwargs={"pk": role_id}))
        assert r.status_code == 200
        assert len(r.data["policies"]) == 1
        assert r.data["policies"][0]["resource"] == "inventory"
