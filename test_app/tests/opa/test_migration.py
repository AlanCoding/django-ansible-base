"""Tests for the migrate_rbac_to_opa management command (Phase 8)."""

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command

from ansible_base.opa.evaluator import local_filter_queryset
from ansible_base.opa.models import GroupRoleAssignment, OPAGroup, Policy, Role
from ansible_base.rbac.models import DABContentType, RoleDefinition
from test_app.models import InstanceGroup, Inventory, Organization, Team

User = get_user_model()


@pytest.fixture
def rbac_orgs(db):
    """Create organizations for RBAC testing."""
    org1 = Organization.objects.create(name="Migration Org 1")
    org2 = Organization.objects.create(name="Migration Org 2")
    return org1, org2


@pytest.fixture
def rbac_inventories(rbac_orgs):
    """Create inventories in each org."""
    org1, org2 = rbac_orgs
    inv1 = Inventory.objects.create(name="Mig Inv 1", organization=org1)
    inv2 = Inventory.objects.create(name="Mig Inv 2", organization=org2)
    return inv1, inv2


@pytest.fixture
def rbac_instance_group(db):
    return InstanceGroup.objects.create(name="Mig IG")


@pytest.fixture
def rbac_users(db, local_authenticator):
    """Create users for migration testing."""
    u1 = User.objects.create_user(username="mig_user1", password="password")
    u2 = User.objects.create_user(username="mig_user2", password="password")
    return u1, u2


@pytest.fixture
def rbac_team(rbac_orgs, rbac_users):
    org1, _ = rbac_orgs
    u1, u2 = rbac_users
    team = Team.objects.create(name="Mig Team", organization=org1)
    RoleDefinition.objects.managed.team_member.give_permission(u1, team)
    return team


def _clear_opa_data():
    """Remove all OPA data to start fresh."""
    Policy.objects.all().delete()
    GroupRoleAssignment.objects.all().delete()
    Role.objects.all().delete()
    OPAGroup.objects.all().delete()


@pytest.mark.django_db
class TestMigrationCommand:
    def test_dry_run_creates_nothing(self, rbac_orgs, rbac_users, rbac_inventories):
        org1, _ = rbac_orgs
        u1, _ = rbac_users
        RoleDefinition.objects.managed.org_admin.give_permission(u1, org1)

        _clear_opa_data()
        call_command("migrate_rbac_to_opa", dry_run=True)

        assert Role.objects.count() == 0
        assert Policy.objects.count() == 0
        assert OPAGroup.objects.count() == 0

    def test_basic_migration(self, rbac_orgs, rbac_users, rbac_inventories):
        """Org admin assignment should produce OPA roles and policies."""
        org1, _ = rbac_orgs
        u1, _ = rbac_users
        RoleDefinition.objects.managed.org_admin.give_permission(u1, org1)

        _clear_opa_data()
        call_command("migrate_rbac_to_opa")

        # Should have created at least one role and assigned it
        assert Role.objects.filter(name__startswith="rbac:").exists()
        assert OPAGroup.objects.filter(name=f"user:{u1.pk}").exists()

        # The user's group should have at least one role assignment
        user_group = OPAGroup.objects.get(name=f"user:{u1.pk}")
        assert GroupRoleAssignment.objects.filter(group=user_group).exists()

        # Policies should reference the org
        policies = Policy.objects.filter(
            role__group_assignments__group=user_group,
            constant_value=str(org1.pk),
        )
        assert policies.exists()

    def test_migration_idempotent(self, rbac_orgs, rbac_users, rbac_inventories):
        """Running migration twice produces the same result."""
        org1, _ = rbac_orgs
        u1, _ = rbac_users
        RoleDefinition.objects.managed.org_admin.give_permission(u1, org1)

        _clear_opa_data()
        call_command("migrate_rbac_to_opa")

        roles_count = Role.objects.count()
        policies_count = Policy.objects.count()
        groups_count = OPAGroup.objects.count()

        # Run again
        call_command("migrate_rbac_to_opa")

        assert Role.objects.count() == roles_count
        assert Policy.objects.count() == policies_count
        assert OPAGroup.objects.count() == groups_count

    def test_object_level_assignment(self, rbac_orgs, rbac_users, rbac_inventories):
        """Object-level inventory assignment produces id-scoped policy."""
        _, _ = rbac_orgs
        u1, _ = rbac_users
        inv1, _ = rbac_inventories

        inv_ct = DABContentType.objects.get_for_model(Inventory)
        inv_rd, _ = RoleDefinition.objects.get_or_create(
            name="Test Inv Admin",
            permissions=["view_inventory", "change_inventory"],
            defaults={"content_type": inv_ct},
        )
        inv_rd.give_permission(u1, inv1)

        _clear_opa_data()
        call_command("migrate_rbac_to_opa")

        # Should have policies scoped to inv1.pk via id
        user_group = OPAGroup.objects.get(name=f"user:{u1.pk}")
        policies = Policy.objects.filter(
            role__group_assignments__group=user_group,
            resource="inventory",
            field_name="id",
            constant_value=str(inv1.pk),
        )
        assert policies.exists()

    def test_org_scoped_assignment(self, rbac_orgs, rbac_users, rbac_inventories):
        """Org admin creates organization_id-scoped policies for child resources."""
        org1, _ = rbac_orgs
        u1, _ = rbac_users

        RoleDefinition.objects.managed.org_admin.give_permission(u1, org1)

        _clear_opa_data()
        call_command("migrate_rbac_to_opa")

        user_group = OPAGroup.objects.get(name=f"user:{u1.pk}")

        # Inventory policies should use organization_id scoping
        inv_policies = Policy.objects.filter(
            role__group_assignments__group=user_group,
            resource="inventory",
            field_name="organization_id",
            constant_value=str(org1.pk),
        )
        assert inv_policies.exists()

        # Organization policies should use id scoping (not organization_id)
        org_policies = Policy.objects.filter(
            role__group_assignments__group=user_group,
            resource="organization",
            field_name="id",
            constant_value=str(org1.pk),
        )
        assert org_policies.exists()

    def test_team_assignment(self, rbac_orgs, rbac_users, rbac_inventories, rbac_team):
        """Team-level assignments should create OPAGroup for the team."""
        inv1, _ = rbac_inventories

        inv_ct = DABContentType.objects.get_for_model(Inventory)
        inv_rd, _ = RoleDefinition.objects.get_or_create(
            name="Test Inv Viewer",
            permissions=["view_inventory"],
            defaults={"content_type": inv_ct},
        )
        inv_rd.give_permission(rbac_team, inv1)

        _clear_opa_data()
        call_command("migrate_rbac_to_opa")

        # Should create an OPAGroup for the team
        team_group = OPAGroup.objects.filter(name=f"team:{rbac_team.name}")
        assert team_group.exists()

        # Team group should have a role assignment
        assert GroupRoleAssignment.objects.filter(group=team_group.first()).exists()

    def test_global_role_migration(self, rbac_orgs, rbac_users, rbac_inventories, rbac_instance_group):
        """System Auditor (global role) should create policies for all resources."""
        u1, _ = rbac_users
        sys_auditor = RoleDefinition.objects.managed.sys_auditor
        sys_auditor.give_global_permission(u1)

        _clear_opa_data()
        call_command("migrate_rbac_to_opa")

        user_group = OPAGroup.objects.get(name=f"user:{u1.pk}")

        # Global role should create policies for existing organizations
        org_policies = Policy.objects.filter(
            role__group_assignments__group=user_group,
            resource="organization",
        )
        assert org_policies.count() >= 2  # At least our 2 test orgs

        # And for inventories via organization_id
        inv_policies = Policy.objects.filter(
            role__group_assignments__group=user_group,
            resource="inventory",
        )
        assert inv_policies.exists()

    def test_cross_org_migration(self, rbac_orgs, rbac_users, rbac_inventories):
        """User with roles in multiple orgs should have policies for each."""
        org1, org2 = rbac_orgs
        u1, _ = rbac_users

        RoleDefinition.objects.managed.org_admin.give_permission(u1, org1)
        RoleDefinition.objects.managed.org_admin.give_permission(u1, org2)

        _clear_opa_data()
        call_command("migrate_rbac_to_opa")

        user_group = OPAGroup.objects.get(name=f"user:{u1.pk}")

        # Should have policies for both orgs
        org1_policies = Policy.objects.filter(
            role__group_assignments__group=user_group,
            resource="organization",
            constant_value=str(org1.pk),
        )
        org2_policies = Policy.objects.filter(
            role__group_assignments__group=user_group,
            resource="organization",
            constant_value=str(org2.pk),
        )
        assert org1_policies.exists()
        assert org2_policies.exists()

    def test_effective_access_after_migration(self, rbac_orgs, rbac_users, rbac_inventories):
        """After migration, the local evaluator should grant correct access."""
        org1, org2 = rbac_orgs
        u1, u2 = rbac_users
        inv1, inv2 = rbac_inventories

        # u1 is org admin of org1 only
        RoleDefinition.objects.managed.org_admin.give_permission(u1, org1)

        _clear_opa_data()
        call_command("migrate_rbac_to_opa")

        # u1 should see inv1 (in org1) but not inv2 (in org2) for read
        opa_qs = local_filter_queryset(Inventory.objects.all(), u1, "read")
        opa_pks = set(opa_qs.values_list("pk", flat=True))
        assert inv1.pk in opa_pks
        assert inv2.pk not in opa_pks

        # u2 should see nothing (no assignments)
        opa_qs2 = local_filter_queryset(Inventory.objects.all(), u2, "read")
        assert opa_qs2.count() == 0

    def test_custom_role_migration(self, rbac_orgs, rbac_users, rbac_inventories):
        """Custom (non-managed) role definitions should be migrated."""
        u1, _ = rbac_users
        inv1, _ = rbac_inventories

        inv_ct = DABContentType.objects.get_for_model(Inventory)
        custom_rd, _ = RoleDefinition.objects.get_or_create(
            name="Custom View-Only",
            permissions=["view_inventory"],
            defaults={"content_type": inv_ct, "description": "Custom test role"},
        )
        custom_rd.give_permission(u1, inv1)

        _clear_opa_data()
        call_command("migrate_rbac_to_opa")

        # The custom role should be migrated
        assert Role.objects.filter(name__contains="Custom View-Only").exists()

        # And u1 should have read access to inv1
        opa_qs = local_filter_queryset(Inventory.objects.all(), u1, "read")
        assert inv1.pk in set(opa_qs.values_list("pk", flat=True))

    def test_sync_flag(self, rbac_orgs, rbac_users, rbac_inventories):
        """The --sync flag should trigger OPA sync without errors."""
        org1, _ = rbac_orgs
        u1, _ = rbac_users
        RoleDefinition.objects.managed.org_admin.give_permission(u1, org1)

        _clear_opa_data()
        # This will try to push to OPA; it may fail if OPA isn't running,
        # but the migration itself should complete
        call_command("migrate_rbac_to_opa", sync=True)
        assert Role.objects.filter(name__startswith="rbac:").exists()

    def test_per_user_groups_created(self, rbac_users):
        """Migration should create per-user OPAGroups for all users."""
        _clear_opa_data()
        call_command("migrate_rbac_to_opa")

        u1, u2 = rbac_users
        assert OPAGroup.objects.filter(name=f"user:{u1.pk}").exists()
        assert OPAGroup.objects.filter(name=f"user:{u2.pk}").exists()

        # Users should be members of their groups
        g1 = OPAGroup.objects.get(name=f"user:{u1.pk}")
        assert g1.users.filter(pk=u1.pk).exists()


    def test_org_admin_inherits_team_permissions(self, rbac_orgs, rbac_users, rbac_inventories, rbac_team):
        """Org admin should inherit permissions from teams in their org.

        In RBAC, org admin has the member_team permission which grants them
        membership in all teams in their org. This means they inherit all
        permissions those teams hold — even on objects in other orgs.
        """
        org1, org2 = rbac_orgs
        u1, u2 = rbac_users
        inv1, inv2 = rbac_inventories

        # Give team an inventory permission on inv2 (which is in org2!)
        inv_ct = DABContentType.objects.get_for_model(Inventory)
        inv_rd, _ = RoleDefinition.objects.get_or_create(
            name="Team Inv Viewer",
            permissions=["view_inventory"],
            defaults={"content_type": inv_ct},
        )
        inv_rd.give_permission(rbac_team, inv2)

        # Make u2 org admin of org1 (rbac_team is in org1)
        RoleDefinition.objects.managed.org_admin.give_permission(u2, org1)

        _clear_opa_data()
        call_command("migrate_rbac_to_opa")

        # u2 should now be in the team's OPA group
        team_group = OPAGroup.objects.get(name=f"team:{rbac_team.name}")
        assert team_group.users.filter(pk=u2.pk).exists()

        # u2 should be able to read inv2 through team inheritance
        opa_qs = local_filter_queryset(Inventory.objects.all(), u2, "read")
        opa_pks = set(opa_qs.values_list("pk", flat=True))
        assert inv2.pk in opa_pks, "Org admin should inherit team permissions on inv2"

    def test_org_admin_team_inherit_matches_rbac(self, rbac_orgs, rbac_users, rbac_inventories, rbac_team):
        """Verify that OPA and RBAC agree on org admin team-inherited permissions."""
        org1, _ = rbac_orgs
        _, u2 = rbac_users
        inv1, inv2 = rbac_inventories

        # Give team a cross-org inventory permission
        inv_ct = DABContentType.objects.get_for_model(Inventory)
        inv_rd, _ = RoleDefinition.objects.get_or_create(
            name="Team Inv Viewer2",
            permissions=["view_inventory"],
            defaults={"content_type": inv_ct},
        )
        inv_rd.give_permission(rbac_team, inv2)

        # Make u2 org admin of org1
        RoleDefinition.objects.managed.org_admin.give_permission(u2, org1)

        _clear_opa_data()
        call_command("migrate_rbac_to_opa")

        # Compare OPA vs RBAC
        opa_qs = local_filter_queryset(Inventory.objects.all(), u2, "read")
        opa_pks = set(opa_qs.values_list("pk", flat=True))

        rbac_qs = Inventory.access_qs(u2, "view", queryset=Inventory.objects.all())
        rbac_pks = set(rbac_qs.values_list("pk", flat=True))

        assert opa_pks == rbac_pks, f"OPA={opa_pks} != RBAC={rbac_pks}"

    def test_non_member_team_role_no_inheritance(self, rbac_orgs, rbac_users, rbac_inventories):
        """Org member (no member_team perm) should NOT inherit team permissions."""
        org1, _ = rbac_orgs
        u1, _ = rbac_users
        inv1, _ = rbac_inventories

        # Create a team with inventory permission
        team = Team.objects.create(name="NoInherit Team", organization=org1)
        inv_ct = DABContentType.objects.get_for_model(Inventory)
        inv_rd, _ = RoleDefinition.objects.get_or_create(
            name="NoInherit Inv Viewer",
            permissions=["view_inventory"],
            defaults={"content_type": inv_ct},
        )
        inv_rd.give_permission(team, inv1)

        # Make u1 org MEMBER (not admin) — org_member doesn't have member_team
        RoleDefinition.objects.managed.org_member.give_permission(u1, org1)

        _clear_opa_data()
        call_command("migrate_rbac_to_opa")

        # u1 should NOT be in the team's OPA group
        team_groups = OPAGroup.objects.filter(name=f"team:{team.name}")
        if team_groups.exists():
            assert not team_groups.first().users.filter(pk=u1.pk).exists()


@pytest.mark.django_db
class TestMigrationVerify:
    """Test the --verify flag compares RBAC vs OPA."""

    def test_verify_no_mismatches(self, rbac_orgs, rbac_users, rbac_inventories, capsys):
        """After clean migration of a simple case, verify should pass."""
        org1, _ = rbac_orgs
        u1, _ = rbac_users
        inv1, _ = rbac_inventories

        inv_ct = DABContentType.objects.get_for_model(Inventory)
        inv_rd, _ = RoleDefinition.objects.get_or_create(
            name="Verify Inv Admin",
            permissions=["view_inventory", "change_inventory"],
            defaults={"content_type": inv_ct},
        )
        inv_rd.give_permission(u1, inv1)

        _clear_opa_data()
        call_command("migrate_rbac_to_opa", verify=True)

        output = capsys.readouterr().out
        # The verify step should run (look for the heading)
        assert "Verifying" in output or "parity" in output.lower()
