"""Tests for OPA delegation — users granting access to resources they have change on.

Tests verify:
- Policy creation gated by change access
- Role assignment gated by group change + delegation check
- Group management gated by opagroup policies
- Privilege escalation prevention
"""

import pytest

from ansible_base.lib.utils.response import get_relative_url
from ansible_base.opa.models import GroupRoleAssignment, OPAGroup, Policy, Role


@pytest.fixture(autouse=True)
def _opa_rest_settings(settings):
    """Override DRF permission classes for OPA group viewset to use OPA.

    The OPAGroupViewSet uses OPAGroupPermission (subclass of OPAPermission)
    which needs the opagroup resource registered.
    """
    pass  # opagroup is now registered in DAB_OPA config


@pytest.mark.django_db
class TestPolicyDelegation:
    """Test that policy creation is gated by change access."""

    def test_superuser_can_create_any_policy(self, admin_api_client, opa_inventory):
        role = Role.objects.create(name="su-policy-role")
        r = admin_api_client.post(
            get_relative_url("opapolicy-list"),
            {
                "role": role.pk,
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

    def test_user_with_change_can_create_policy(
        self, opa_user_client, opa_user, opa_inventory, grant_opa_role
    ):
        """User with change on an inventory can create a read policy for it."""
        grant_opa_role(
            opa_user,
            "deleg-inv-changer",
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

        role = Role.objects.create(name="user-deleg-role")
        r = opa_user_client.post(
            get_relative_url("opapolicy-list"),
            {
                "role": role.pk,
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

    def test_user_without_change_cannot_create_policy(
        self, opa_user_client, opa_user, opa_inventory, grant_opa_role
    ):
        """User with only read on an inventory cannot create a policy for it."""
        grant_opa_role(
            opa_user,
            "deleg-inv-reader-only",
            [
                {
                    "resource": "inventory",
                    "action": "read",
                    "field_name": "id",
                    "constant_value": str(opa_inventory.pk),
                },
            ],
        )

        role = Role.objects.create(name="reader-deleg-role")
        r = opa_user_client.post(
            get_relative_url("opapolicy-list"),
            {
                "role": role.pk,
                "resource": "inventory",
                "action": "read",
                "field_name": "id",
                "operator": "eq",
                "value_type": "constant",
                "constant_value": str(opa_inventory.pk),
            },
            format="json",
        )
        assert r.status_code == 403

    def test_user_cannot_create_policy_for_unowned_resource(
        self, opa_user_client, opa_user, opa_inventory, opa_inventory2, grant_opa_role
    ):
        """User with change on inventory 1 cannot create policy for inventory 2."""
        grant_opa_role(
            opa_user,
            "deleg-inv1-changer",
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

        role = Role.objects.create(name="escalation-role")
        r = opa_user_client.post(
            get_relative_url("opapolicy-list"),
            {
                "role": role.pk,
                "resource": "inventory",
                "action": "read",
                "field_name": "id",
                "operator": "eq",
                "value_type": "constant",
                "constant_value": str(opa_inventory2.pk),
            },
            format="json",
        )
        assert r.status_code == 403

    def test_org_scoped_change_allows_org_scoped_policy(
        self, opa_user_client, opa_user, opa_org, grant_opa_role
    ):
        """User with org-scoped change can create org-scoped policies."""
        grant_opa_role(
            opa_user,
            "deleg-org-inv-changer",
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
                    "field_name": "organization_id",
                    "constant_value": str(opa_org.pk),
                },
            ],
        )

        role = Role.objects.create(name="org-scope-deleg-role")
        r = opa_user_client.post(
            get_relative_url("opapolicy-list"),
            {
                "role": role.pk,
                "resource": "inventory",
                "action": "read",
                "field_name": "organization_id",
                "operator": "eq",
                "value_type": "constant",
                "constant_value": str(opa_org.pk),
            },
            format="json",
        )
        assert r.status_code == 201

    def test_object_scoped_change_cannot_create_org_scoped_policy(
        self, opa_user_client, opa_user, opa_inventory, opa_org, grant_opa_role
    ):
        """User with id-scoped change cannot escalate to org-scoped policy."""
        grant_opa_role(
            opa_user,
            "deleg-inv-id-changer",
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

        role = Role.objects.create(name="escalation-org-role")
        r = opa_user_client.post(
            get_relative_url("opapolicy-list"),
            {
                "role": role.pk,
                "resource": "inventory",
                "action": "read",
                "field_name": "organization_id",
                "operator": "eq",
                "value_type": "constant",
                "constant_value": str(opa_org.pk),
            },
            format="json",
        )
        assert r.status_code == 403

    def test_principal_user_id_policy_requires_superuser(
        self, opa_user_client, opa_user, opa_inventory, grant_opa_role
    ):
        """Regular users cannot create principal_user_id policies."""
        grant_opa_role(
            opa_user,
            "deleg-inv-changer-for-puid",
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

        role = Role.objects.create(name="puid-role")
        r = opa_user_client.post(
            get_relative_url("opapolicy-list"),
            {
                "role": role.pk,
                "resource": "inventory",
                "action": "read",
                "field_name": "created_by_id",
                "operator": "eq",
                "value_type": "principal_user_id",
            },
            format="json",
        )
        assert r.status_code == 403

    def test_policies_are_immutable(self, admin_api_client, opa_inventory):
        """Policies cannot be updated — only created and deleted."""
        role = Role.objects.create(name="immutable-test-role")
        policy = Policy.objects.create(
            role=role,
            resource="inventory",
            action="read",
            field_name="id",
            operator="eq",
            value_type="constant",
            constant_value=str(opa_inventory.pk),
        )
        r = admin_api_client.patch(
            get_relative_url("opapolicy-detail", kwargs={"pk": policy.pk}),
            {"constant_value": "999"},
            format="json",
        )
        assert r.status_code == 405


@pytest.mark.django_db
class TestRoleOwnership:
    """Test that role update/delete is limited to creator."""

    def test_creator_can_update_role(self, opa_user_client, opa_user):
        role = Role.objects.create(name="owned-role", created_by=opa_user)
        r = opa_user_client.patch(
            get_relative_url("oparole-detail", kwargs={"pk": role.pk}),
            {"description": "updated"},
            format="json",
        )
        assert r.status_code == 200

    def test_non_creator_cannot_update_role(self, opa_user2_client, opa_user):
        role = Role.objects.create(name="other-owned-role", created_by=opa_user)
        r = opa_user2_client.patch(
            get_relative_url("oparole-detail", kwargs={"pk": role.pk}),
            {"description": "hacked"},
            format="json",
        )
        assert r.status_code == 403

    def test_non_creator_cannot_delete_role(self, opa_user2_client, opa_user):
        role = Role.objects.create(name="del-other-role", created_by=opa_user)
        r = opa_user2_client.delete(
            get_relative_url("oparole-detail", kwargs={"pk": role.pk}),
        )
        assert r.status_code == 403

    def test_superuser_can_update_any_role(self, admin_api_client, opa_user):
        role = Role.objects.create(name="su-update-role", created_by=opa_user)
        r = admin_api_client.patch(
            get_relative_url("oparole-detail", kwargs={"pk": role.pk}),
            {"description": "su update"},
            format="json",
        )
        assert r.status_code == 200


@pytest.mark.django_db
class TestAssignmentDelegation:
    """Test that role assignment requires group change + delegation check."""

    def test_superuser_can_assign_any_role(self, admin_api_client, opa_inventory):
        group = OPAGroup.objects.create(name="su-assign-group")
        role = Role.objects.create(name="su-assign-role")
        Policy.objects.create(
            role=role,
            resource="inventory",
            action="read",
            field_name="id",
            operator="eq",
            value_type="constant",
            constant_value=str(opa_inventory.pk),
        )
        r = admin_api_client.post(
            get_relative_url("opagrouproleassignment-list"),
            {"group": group.pk, "role": role.pk},
            format="json",
        )
        assert r.status_code == 201

    def test_user_can_assign_role_with_group_change_and_delegation(
        self, opa_user_client, opa_user, opa_inventory, opa_org, grant_opa_role
    ):
        """User with change on group and change on inventory can assign."""
        target_group = OPAGroup.objects.create(name="deleg-target-group", organization=opa_org)

        # Grant: change on inventories in org + change on the target group
        grant_opa_role(
            opa_user,
            "deleg-assign-perms",
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
                    "field_name": "organization_id",
                    "constant_value": str(opa_org.pk),
                },
                {
                    "resource": "opagroup",
                    "action": "read",
                    "field_name": "id",
                    "constant_value": str(target_group.pk),
                },
                {
                    "resource": "opagroup",
                    "action": "change",
                    "field_name": "id",
                    "constant_value": str(target_group.pk),
                },
            ],
        )

        # Create a role with an inventory read policy
        role = Role.objects.create(name="deleg-inv-reader-role")
        Policy.objects.create(
            role=role,
            resource="inventory",
            action="read",
            field_name="organization_id",
            operator="eq",
            value_type="constant",
            constant_value=str(opa_org.pk),
        )

        r = opa_user_client.post(
            get_relative_url("opagrouproleassignment-list"),
            {"group": target_group.pk, "role": role.pk},
            format="json",
        )
        assert r.status_code == 201

    def test_user_without_group_change_cannot_assign(
        self, opa_user_client, opa_user, opa_inventory, opa_org, grant_opa_role
    ):
        """User without change on the group cannot assign roles to it."""
        target_group = OPAGroup.objects.create(name="no-change-group", organization=opa_org)

        # Grant inventory change but NOT group change
        grant_opa_role(
            opa_user,
            "deleg-no-group-change",
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
                    "field_name": "organization_id",
                    "constant_value": str(opa_org.pk),
                },
            ],
        )

        role = Role.objects.create(name="no-group-role")
        Policy.objects.create(
            role=role,
            resource="inventory",
            action="read",
            field_name="organization_id",
            operator="eq",
            value_type="constant",
            constant_value=str(opa_org.pk),
        )

        r = opa_user_client.post(
            get_relative_url("opagrouproleassignment-list"),
            {"group": target_group.pk, "role": role.pk},
            format="json",
        )
        assert r.status_code == 403

    def test_user_without_delegation_cannot_assign(
        self, opa_user_client, opa_user, opa_inventory, opa_org, grant_opa_role
    ):
        """User with group change but without resource change cannot assign."""
        target_group = OPAGroup.objects.create(name="no-deleg-group", organization=opa_org)

        # Grant group change but only inventory READ (not change)
        grant_opa_role(
            opa_user,
            "deleg-no-resource-change",
            [
                {
                    "resource": "inventory",
                    "action": "read",
                    "field_name": "organization_id",
                    "constant_value": str(opa_org.pk),
                },
                {
                    "resource": "opagroup",
                    "action": "read",
                    "field_name": "id",
                    "constant_value": str(target_group.pk),
                },
                {
                    "resource": "opagroup",
                    "action": "change",
                    "field_name": "id",
                    "constant_value": str(target_group.pk),
                },
            ],
        )

        role = Role.objects.create(name="no-deleg-role")
        Policy.objects.create(
            role=role,
            resource="inventory",
            action="read",
            field_name="organization_id",
            operator="eq",
            value_type="constant",
            constant_value=str(opa_org.pk),
        )

        r = opa_user_client.post(
            get_relative_url("opagrouproleassignment-list"),
            {"group": target_group.pk, "role": role.pk},
            format="json",
        )
        assert r.status_code == 403


@pytest.mark.django_db
class TestGroupManagement:
    """Test that group management uses OPA-based access control."""

    def test_superuser_can_create_group(self, admin_api_client, opa_org):
        r = admin_api_client.post(
            get_relative_url("opagroup-list"),
            {"name": "su-new-group", "organization": opa_org.pk},
            format="json",
        )
        assert r.status_code == 201

    def test_user_with_opagroup_change_can_add_user(
        self, opa_user_client, opa_user, opa_user2, opa_org, grant_opa_role
    ):
        """Team admin (opagroup.change) can add users to the group."""
        group = OPAGroup.objects.create(name="team-admin-group", organization=opa_org)
        grant_opa_role(
            opa_user,
            "team-admin-perms",
            [
                {
                    "resource": "opagroup",
                    "action": "read",
                    "field_name": "id",
                    "constant_value": str(group.pk),
                },
                {
                    "resource": "opagroup",
                    "action": "change",
                    "field_name": "id",
                    "constant_value": str(group.pk),
                },
            ],
        )

        r = opa_user_client.post(
            get_relative_url("opagroup-add-user", kwargs={"pk": group.pk}),
            {"user_id": opa_user2.pk},
            format="json",
        )
        assert r.status_code == 200
        assert group.users.filter(pk=opa_user2.pk).exists()

    def test_user_without_opagroup_change_cannot_add_user(
        self, opa_user_client, opa_user, opa_user2, opa_org, grant_opa_role
    ):
        """User without change on group cannot add users."""
        group = OPAGroup.objects.create(name="no-admin-group", organization=opa_org)
        # Only read, no change
        grant_opa_role(
            opa_user,
            "group-reader-only",
            [
                {
                    "resource": "opagroup",
                    "action": "read",
                    "field_name": "id",
                    "constant_value": str(group.pk),
                },
            ],
        )

        r = opa_user_client.post(
            get_relative_url("opagroup-add-user", kwargs={"pk": group.pk}),
            {"user_id": opa_user2.pk},
            format="json",
        )
        assert r.status_code == 403


@pytest.mark.django_db
class TestEndToEndDelegation:
    """Test a complete delegation flow."""

    def test_org_admin_delegates_to_team(
        self, admin_api_client, opa_user_client, opa_user, opa_user2, opa_inventory, opa_org, grant_opa_role
    ):
        """Superuser bootstraps org admin, org admin delegates to a team."""
        # Step 1: Superuser grants org admin to opa_user
        grant_opa_role(
            opa_user,
            "org-admin-role",
            [
                {
                    "resource": "organization",
                    "action": "read",
                    "field_name": "id",
                    "constant_value": str(opa_org.pk),
                },
                {
                    "resource": "organization",
                    "action": "change",
                    "field_name": "id",
                    "constant_value": str(opa_org.pk),
                },
                {
                    "resource": "inventory",
                    "action": "read",
                    "field_name": "organization_id",
                    "constant_value": str(opa_org.pk),
                },
                {
                    "resource": "inventory",
                    "action": "change",
                    "field_name": "organization_id",
                    "constant_value": str(opa_org.pk),
                },
                {
                    "resource": "opagroup",
                    "action": "read",
                    "field_name": "organization_id",
                    "constant_value": str(opa_org.pk),
                },
                {
                    "resource": "opagroup",
                    "action": "change",
                    "field_name": "organization_id",
                    "constant_value": str(opa_org.pk),
                },
                {
                    "resource": "opagroup",
                    "action": "add",
                    "field_name": "organization_id",
                    "constant_value": str(opa_org.pk),
                },
            ],
        )

        # Step 2: Org admin creates a team (OPAGroup)
        r = opa_user_client.post(
            get_relative_url("opagroup-list"),
            {"name": "DevOps Team", "organization": opa_org.pk},
            format="json",
        )
        assert r.status_code == 201, r.data
        team_id = r.data["id"]

        # Step 3: Org admin adds opa_user2 to the team
        r = opa_user_client.post(
            get_relative_url("opagroup-add-user", kwargs={"pk": team_id}),
            {"user_id": opa_user2.pk},
            format="json",
        )
        assert r.status_code == 200

        # Step 4: Org admin creates a role with inventory read policy
        r = opa_user_client.post(
            get_relative_url("oparole-list"),
            {"name": "org5-inv-reader"},
            format="json",
        )
        assert r.status_code == 201
        role_id = r.data["id"]

        # Step 5: Org admin creates a policy on that role
        r = opa_user_client.post(
            get_relative_url("opapolicy-list"),
            {
                "role": role_id,
                "resource": "inventory",
                "action": "read",
                "field_name": "organization_id",
                "operator": "eq",
                "value_type": "constant",
                "constant_value": str(opa_org.pk),
            },
            format="json",
        )
        assert r.status_code == 201

        # Step 6: Org admin assigns the role to the team
        r = opa_user_client.post(
            get_relative_url("opagrouproleassignment-list"),
            {"group": team_id, "role": role_id},
            format="json",
        )
        assert r.status_code == 201

        # Step 7: Verify opa_user2 now has effective scope for inventory read
        r = admin_api_client.get(
            get_relative_url("opa-effective-scope"),
            {"user_id": opa_user2.pk, "resource": "inventory", "action": "read"},
        )
        assert r.status_code == 200
        assert r.data["allow"] is True
        assert any(
            c["field_name"] == "organization_id" and c["value"] == opa_org.pk
            for c in r.data["clauses"]
        )
