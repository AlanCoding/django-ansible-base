"""
Adversarial tests for _recompute_after_give / _recompute_after_remove
after AAP-87982 (PR #1101) changed the descendant expansion order.

Goal: prove that RoleEvaluation entries stay correct after every
give_permission / remove_permission involving teams, including
multi-layer inheritance, overlapping assignments, and interleaved
give/remove sequences.
"""
import pytest

from ansible_base.rbac.models import ObjectRole, RoleDefinition, RoleEvaluation
from ansible_base.rbac.permission_registry import permission_registry
from test_app.models import Inventory, Organization


@pytest.mark.django_db
class TestTeamOrgInheritance:
    """Team gets an org-level role, then a direct child-object role.
    Both evaluation paths must produce correct results."""

    def test_team_org_admin_then_direct_inv_role(self, organization, inventory, team, inv_rd, member_rd, org_inv_change_rd):
        """Give team org-level inv role (cascades to all children), then also give
        team a direct inventory role. Both sets of evaluations must exist.
        Then remove the direct role — org-cascaded evaluations must survive."""
        user = permission_registry.user_model.objects.create(username='adv_user1')

        member_rd.give_permission(user, team)
        org_inv_change_rd.give_permission(team, organization)

        assert user.has_obj_perm(inventory, 'change_inventory')
        assert user.has_obj_perm(inventory, 'view_inventory')
        assert inventory in set(Inventory.access_qs(user))

        # Now also give team a direct inventory role
        inv_rd.give_permission(team, inventory)

        # User should still see inventory (via both paths)
        assert user.has_obj_perm(inventory, 'change_inventory')
        assert user.has_obj_perm(inventory, 'view_inventory')

        # Remove the direct inventory role
        inv_rd.remove_permission(team, inventory)

        # User should STILL see inventory via org cascade
        assert user.has_obj_perm(inventory, 'change_inventory'), \
            "Removing direct inv role broke org-cascaded evaluations"
        assert user.has_obj_perm(inventory, 'view_inventory'), \
            "Removing direct inv role broke org-cascaded evaluations"

    def test_direct_inv_role_then_org_role(self, organization, inventory, team, inv_rd, member_rd, org_inv_change_rd):
        """Reverse order: give team direct inventory role first, then org-level inv role.
        Both must work, and removing org role must leave direct role intact."""
        user = permission_registry.user_model.objects.create(username='adv_user2')

        member_rd.give_permission(user, team)
        inv_rd.give_permission(team, inventory)

        assert user.has_obj_perm(inventory, 'change_inventory')

        # Now add org-level inv role
        org_inv_change_rd.give_permission(team, organization)
        assert user.has_obj_perm(inventory, 'change_inventory')

        # Remove org-level inv role
        org_inv_change_rd.remove_permission(team, organization)

        # Direct inv role should still work
        assert user.has_obj_perm(inventory, 'change_inventory'), \
            "Removing org role broke direct inventory role evaluations"


@pytest.mark.django_db
class TestMultipleTeamsSameObject:
    """Two teams both get roles on the same inventory.
    Removing one team's assignment must not affect the other."""

    def test_two_teams_one_inventory(self, organization, inventory, inv_rd, member_rd):
        team1 = permission_registry.team_model.objects.create(name='adv-team-A', organization=organization)
        team2 = permission_registry.team_model.objects.create(name='adv-team-B', organization=organization)
        user1 = permission_registry.user_model.objects.create(username='adv_user_t1')
        user2 = permission_registry.user_model.objects.create(username='adv_user_t2')

        member_rd.give_permission(user1, team1)
        member_rd.give_permission(user2, team2)

        inv_rd.give_permission(team1, inventory)
        inv_rd.give_permission(team2, inventory)

        assert user1.has_obj_perm(inventory, 'change')
        assert user2.has_obj_perm(inventory, 'change')

        # Remove team1's assignment
        inv_rd.remove_permission(team1, inventory)

        assert not user1.has_obj_perm(inventory, 'change'), \
            "User1 still has perms after team1 lost the role"
        assert user2.has_obj_perm(inventory, 'change'), \
            "Removing team1's role broke team2's evaluations"


@pytest.mark.django_db
class TestGiveRemoveGiveSequence:
    """Give, remove, re-give the same permission and verify evaluations
    are correct at every step."""

    def test_give_remove_regive_team_inv(self, organization, inventory, team, inv_rd, member_rd):
        user = permission_registry.user_model.objects.create(username='adv_user_grg')
        member_rd.give_permission(user, team)

        inv_ct_id = permission_registry.content_type_model.objects.get_for_model(Inventory).id

        # Give
        inv_rd.give_permission(team, inventory)
        assert user.has_obj_perm(inventory, 'change')
        evals_after_give = RoleEvaluation.objects.filter(
            object_id=inventory.pk, content_type_id=inv_ct_id,
        ).count()
        assert evals_after_give > 0

        # Remove
        inv_rd.remove_permission(team, inventory)
        assert not user.has_obj_perm(inventory, 'change')

        # Re-give
        inv_rd.give_permission(team, inventory)
        assert user.has_obj_perm(inventory, 'change'), \
            "Re-giving permission after remove didn't restore evaluations"
        evals_after_regive = RoleEvaluation.objects.filter(
            object_id=inventory.pk, content_type_id=inv_ct_id,
        ).count()
        assert evals_after_regive == evals_after_give, \
            f"Evaluation count changed after give-remove-regive: {evals_after_give} -> {evals_after_regive}"


@pytest.mark.django_db
class TestOrgTeamCascadeEvaluations:
    """Assign org-level role to a team. Verify evaluations exist for
    child objects created BEFORE and AFTER the role assignment."""

    def test_child_objects_before_role_assignment(self, organization, inventory, team, member_rd, org_inv_change_rd):
        """Inventory exists before org role is assigned to team.
        User (team member) must see it."""
        user = permission_registry.user_model.objects.create(username='adv_cascade1')

        member_rd.give_permission(user, team)
        # Inventory already exists
        org_inv_change_rd.give_permission(team, organization)

        assert user.has_obj_perm(inventory, 'view'), \
            "Team member can't see inventory created before org role assignment"
        assert inventory in set(Inventory.access_qs(user, 'view'))

    def test_child_objects_after_role_assignment(self, organization, team, member_rd, org_inv_change_rd):
        """Inventory created AFTER org role is assigned to team.
        User (team member) must see the new inventory too."""
        user = permission_registry.user_model.objects.create(username='adv_cascade2')

        member_rd.give_permission(user, team)
        org_inv_change_rd.give_permission(team, organization)

        # Create inventory AFTER role assignment
        new_inv = Inventory.objects.create(name='adv-post-assign-inv', organization=organization)

        assert user.has_obj_perm(new_inv, 'view'), \
            "Team member can't see inventory created after org role assignment"
        assert new_inv in set(Inventory.access_qs(user, 'view'))


@pytest.mark.django_db
class TestUserAndTeamOnSameObject:
    """User has a direct role AND is a member of a team that also has a role
    on the same object. Removing one must not affect the other."""

    def test_user_direct_plus_team_indirect(self, organization, inventory, team, inv_rd, member_rd):
        user = permission_registry.user_model.objects.create(username='adv_both')

        # User gets direct role
        inv_rd.give_permission(user, inventory)
        assert user.has_obj_perm(inventory, 'change')

        # User also gets role via team
        member_rd.give_permission(user, team)
        inv_rd.give_permission(team, inventory)
        assert user.has_obj_perm(inventory, 'change')

        # Remove team's role
        inv_rd.remove_permission(team, inventory)
        assert user.has_obj_perm(inventory, 'change'), \
            "Removing team role broke user's direct role evaluations"

        # Remove user's direct role
        inv_rd.remove_permission(user, inventory)
        assert not user.has_obj_perm(inventory, 'change')

    def test_remove_direct_keep_team(self, organization, inventory, team, inv_rd, member_rd):
        user = permission_registry.user_model.objects.create(username='adv_both2')

        inv_rd.give_permission(user, inventory)
        member_rd.give_permission(user, team)
        inv_rd.give_permission(team, inventory)

        # Remove user's direct role — team role should still work
        inv_rd.remove_permission(user, inventory)
        assert user.has_obj_perm(inventory, 'change'), \
            "Removing user's direct role broke team-based evaluations"


@pytest.mark.django_db
class TestBulkGiveTeamPermissions:
    """Use bulk_give_permissions with multiple team assignments in one call.
    This directly exercises _recompute_after_give with multiple teams."""

    def test_bulk_give_two_teams_different_objects(self, organization, inventory, inv_rd, member_rd):
        from ansible_base.rbac.pipeline import bulk_give_permissions

        team1 = permission_registry.team_model.objects.create(name='adv-bulk-t1', organization=organization)
        team2 = permission_registry.team_model.objects.create(name='adv-bulk-t2', organization=organization)
        inv2 = Inventory.objects.create(name='adv-bulk-inv2', organization=organization)

        user1 = permission_registry.user_model.objects.create(username='adv_bulk1')
        user2 = permission_registry.user_model.objects.create(username='adv_bulk2')

        member_rd.give_permission(user1, team1)
        member_rd.give_permission(user2, team2)

        # Bulk assign: team1 -> inventory, team2 -> inv2
        bulk_give_permissions(
            team_permissions=[
                (inv_rd, team1, inventory),
                (inv_rd, team2, inv2),
            ]
        )

        assert user1.has_obj_perm(inventory, 'change'), \
            "Bulk give: user1 can't access inventory via team1"
        assert user2.has_obj_perm(inv2, 'change'), \
            "Bulk give: user2 can't access inv2 via team2"
        assert not user1.has_obj_perm(inv2, 'change')
        assert not user2.has_obj_perm(inventory, 'change')

    def test_bulk_give_team_org_role(self, organization, inventory, member_rd, org_inv_change_rd):
        """Bulk give org-level role to a team. Evaluations for child
        objects must be created."""
        from ansible_base.rbac.pipeline import bulk_give_permissions

        team = permission_registry.team_model.objects.create(name='adv-bulk-org-t', organization=organization)
        user = permission_registry.user_model.objects.create(username='adv_bulk_org')

        member_rd.give_permission(user, team)
        bulk_give_permissions(team_permissions=[(org_inv_change_rd, team, organization)])

        assert user.has_obj_perm(inventory, 'view'), \
            "Bulk give org role to team: user can't see child inventory"


@pytest.mark.django_db
class TestOrgRoleTeamThenNewTeamMember:
    """Team already has org-level role. A NEW user joins the team.
    The new user must immediately see the org's child objects."""

    def test_new_member_inherits_team_org_perms(self, organization, inventory, team, member_rd, org_inv_change_rd):
        # Team gets org role first
        org_inv_change_rd.give_permission(team, organization)

        # New user joins team AFTER org role was assigned
        late_user = permission_registry.user_model.objects.create(username='adv_late_joiner')
        member_rd.give_permission(late_user, team)

        assert late_user.has_obj_perm(inventory, 'view'), \
            "Late team joiner can't see inventory from pre-existing org role"
        assert late_user.has_obj_perm(organization, 'view'), \
            "Late team joiner can't see organization"


@pytest.mark.django_db
class TestBulkMixedUserAndTeam:
    """Bulk assign with both user and team assignments in a single call.
    This tests that _recompute_after_give handles the mixed case."""

    def test_bulk_mixed_assignments(self, organization, inventory, inv_rd, member_rd):
        from ansible_base.rbac.pipeline import bulk_give_permissions

        team = permission_registry.team_model.objects.create(name='adv-mixed-t', organization=organization)
        user1 = permission_registry.user_model.objects.create(username='adv_mixed1')
        user2 = permission_registry.user_model.objects.create(username='adv_mixed2')
        inv2 = Inventory.objects.create(name='adv-mixed-inv2', organization=organization)

        member_rd.give_permission(user2, team)

        # Bulk: user1 gets direct inv role, team gets inv2 role
        bulk_give_permissions(
            user_permissions=[(inv_rd, user1, inventory)],
            team_permissions=[(inv_rd, team, inv2)],
        )

        assert user1.has_obj_perm(inventory, 'change'), \
            "Bulk mixed: user1 direct assignment failed"
        assert user2.has_obj_perm(inv2, 'change'), \
            "Bulk mixed: user2 team-based assignment failed"
        assert not user1.has_obj_perm(inv2, 'change')
        assert not user2.has_obj_perm(inventory, 'change')


@pytest.mark.django_db
class TestRecomputeIdempotency:
    """Verify that running recompute_role_evaluations produces the same
    result as the incremental give_permission path. This catches any case
    where the fix might skip a needed recomputation."""

    def test_give_then_full_recompute_matches(self, organization, inventory, team, inv_rd, member_rd, org_inv_change_rd):
        from ansible_base.rbac.caching import recompute_role_evaluations

        user = permission_registry.user_model.objects.create(username='adv_idempotent')
        member_rd.give_permission(user, team)
        org_inv_change_rd.give_permission(team, organization)
        inv_rd.give_permission(team, inventory)

        # Snapshot evaluations after incremental gives
        evals_before = set(
            RoleEvaluation.objects.values_list('codename', 'content_type_id', 'role_id', 'object_id')
        )

        # Force full recompute of all affected ObjectRoles
        all_roles = ObjectRole.objects.all().prefetch_related('provides_teams__has_roles')
        recompute_role_evaluations(all_roles)

        # Snapshot after full recompute
        evals_after = set(
            RoleEvaluation.objects.values_list('codename', 'content_type_id', 'role_id', 'object_id')
        )

        missing = evals_after - evals_before
        extra = evals_before - evals_after

        assert not missing, f"Incremental give_permission missed evaluations that full recompute found: {missing}"
        assert not extra, f"Incremental give_permission created extra evaluations not in full recompute: {extra}"


@pytest.mark.django_db
class TestOrgTeamMembershipViaOrgRole:
    """Give org-team-member role to a team (team A gets membership in team B
    via org role), then team B has an inventory role. User in team A should
    transitively access the inventory."""

    def test_transitive_team_membership(self, organization, inventory, inv_rd, member_rd, org_team_member_rd):
        team_a = permission_registry.team_model.objects.create(name='adv-trans-A', organization=organization)
        team_b = permission_registry.team_model.objects.create(name='adv-trans-B', organization=organization)
        user = permission_registry.user_model.objects.create(username='adv_transitive')

        # User -> team_a member
        member_rd.give_permission(user, team_a)

        # team_a gets org-level team membership (makes team_a a member of all teams in org)
        org_team_member_rd.give_permission(team_a, organization)

        # team_b gets inventory role
        inv_rd.give_permission(team_b, inventory)

        # User should see inventory via: user -> team_a -> (org member) -> team_b -> inventory
        assert user.has_obj_perm(inventory, 'change'), \
            "Transitive team membership didn't grant inventory access"

    def test_remove_transitive_path(self, organization, inventory, inv_rd, member_rd, org_team_member_rd):
        """Remove the org-team-member role from team_a. User should lose
        transitive access to inventory via team_b."""
        team_a = permission_registry.team_model.objects.create(name='adv-trans-rm-A', organization=organization)
        team_b = permission_registry.team_model.objects.create(name='adv-trans-rm-B', organization=organization)
        user = permission_registry.user_model.objects.create(username='adv_trans_rm')

        member_rd.give_permission(user, team_a)
        org_team_member_rd.give_permission(team_a, organization)
        inv_rd.give_permission(team_b, inventory)

        assert user.has_obj_perm(inventory, 'change')

        # Remove org-team-member from team_a
        org_team_member_rd.remove_permission(team_a, organization)

        assert not user.has_obj_perm(inventory, 'change'), \
            "Removing transitive team membership didn't revoke inventory access"
