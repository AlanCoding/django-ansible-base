import pytest
from django.core.exceptions import ValidationError
from django.test.utils import override_settings

from ansible_base.models.rbac import RoleDefinition, RoleEvaluation
from ansible_base.rbac.permission_registry import permission_registry
from ansible_base.tests.functional.models import Inventory, Organization


@pytest.mark.django_db
def test_invalid_actor(inventory, org_inv_rd):
    with pytest.raises(RuntimeError) as exc:
        org_inv_rd.give_permission(inventory, inventory)  # makes no sense
    assert 'must be a user or team' in str(exc)


@pytest.mark.django_db
def test_child_object_permission(rando, organization, inventory, org_inv_rd):
    assert inventory.organization == organization

    assert set(RoleEvaluation.accessible_objects(Organization, rando, 'change')) == set()
    assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change')) == set()

    org_inv_rd.give_permission(rando, organization)

    assert set(RoleEvaluation.accessible_objects(Organization, rando, 'change_organization')) == set([organization])
    assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([inventory])


@pytest.mark.django_db
def test_organization_permission_change(org_inv_rd):
    "Test that when an inventory is moved from orgA to orgB, the permissions are correctly updated"
    userA = permission_registry.user_model.objects.create(username='A')
    orgA = Organization.objects.create(name='orgA')
    userB = permission_registry.user_model.objects.create(username='B')
    orgB = Organization.objects.create(name='orgB')

    org_inv_rd.give_permission(userA, orgA)
    org_inv_rd.give_permission(userB, orgB)

    inv = Inventory.objects.create(name='mooover-inventory', organization=orgA)

    # Inventory belongs with organization A, so all permissions active there apply to it
    assert set(RoleEvaluation.accessible_objects(Inventory, userA, 'change_inventory')) == set([inv])
    assert set(RoleEvaluation.accessible_objects(Inventory, userB, 'change_inventory')) == set([])

    inv.organization = orgB
    inv.save()

    # Permissions are reversed, as inventory is now a part of organization B
    assert set(RoleEvaluation.accessible_objects(Inventory, userA, 'change_inventory')) == set([])
    assert set(RoleEvaluation.accessible_objects(Inventory, userB, 'change_inventory')) == set([inv])


@pytest.mark.django_db
@pytest.mark.parametrize('order', ['role_first', 'obj_first'])
def test_later_created_child_object_permission(rando, organization, order, org_inv_rd):
    assert set(RoleEvaluation.accessible_objects(Organization, rando, 'change')) == set()
    assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change')) == set()

    if order == 'role_first':
        org_inv_rd.give_permission(rando, organization)
        inventory = Inventory.objects.create(name='for-test', organization=organization)
    else:
        inventory = Inventory.objects.create(name='for-test', organization=organization)
        org_inv_rd.give_permission(rando, organization)

    assert set(RoleEvaluation.accessible_objects(Organization, rando, 'change_organization')) == set([organization])
    assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([inventory])


@pytest.mark.django_db
class TestTeamAssignment:
    def test_object_team_assignment(self, rando, inventory, team, member_rd, inv_rd):
        member_or = member_rd.give_permission(rando, team)
        assert set(member_or.provides_teams.all()) == set([team])
        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([])
        inv_or = inv_rd.give_permission(team, inventory)
        assert team in inv_or.teams.all()

        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([inventory])

        # revoking team access to inventory should revoke permissions obtained from the team
        inv_rd.remove_permission(team, inventory)
        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([])

    def test_object_team_assignment_reverse(self, rando, inventory, team, member_rd, inv_rd):
        "Same as test_object_team_assignment but with the order of operations reversed"
        inv_or = inv_rd.give_permission(team, inventory)
        assert team in inv_or.teams.all()
        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([])
        member_or = member_rd.give_permission(rando, team)
        assert set(member_or.provides_teams.all()) == set([team])

        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([inventory])

        # revoking team membership should revoke permissions obtained from the team
        member_rd.remove_permission(rando, team)
        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([])

    def test_five_nested_teams(self, rando, organization, member_rd, inv_rd):
        inv = Inventory.objects.create(name='inv', organization=organization)
        teams = [permission_registry.team_model.objects.create(name=f'team-{i}', organization=organization) for i in range(5)]
        for parent_team, child_team in zip(teams[:-1], teams[1:]):
            member_or = member_rd.give_permission(parent_team, child_team)
            assert child_team in set(member_or.provides_teams.all())
        inv_rd.give_permission(teams[-1], inv)
        member_or = member_rd.give_permission(rando, teams[0])
        assert list(member_or.users.all()) == [rando]
        assert set(member_or.provides_teams.all()) == set(teams)
        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([inv])

        # remove a team in the middle and confirm the effect works
        member_rd.remove_permission(teams[2], teams[3])
        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([])
        # confirm that adding the team back also works
        member_or = member_rd.give_permission(teams[2], teams[3])
        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([inv])
        # now delete a middle team should have a similar effecct, also breaking the chain
        teams[3].delete()
        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([])

    def test_teams_with_loops(self, rando, inventory, organization, member_rd, inv_rd):
        "This creates team memberships with a non-trivial loop and checks for infinite recursion"
        teamA = permission_registry.team_model.objects.create(name='teamA', organization=organization)
        teamB = permission_registry.team_model.objects.create(name='teamB', organization=organization)
        teamC = permission_registry.team_model.objects.create(name='teamC', organization=organization)

        member_rd.give_permission(teamA, teamB)
        member_rd.give_permission(teamB, teamC)
        member_rd.give_permission(teamC, teamA)

        member_rd.give_permission(rando, teamA)
        inv_rd.give_permission(teamC, inventory)

        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([inventory])

        teamC.delete()
        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([])


@pytest.mark.django_db
class TestOrgTeamMemberAssignment:
    def test_organization_team_assignment(self, rando, organization, member_rd, inv_rd):
        assert permission_registry.permission_model.objects.filter(codename='member_team').exists()  # sanity
        inv1 = Inventory.objects.create(name='inv1', organization=organization)
        inv2 = Inventory.objects.create(name='inv2', organization=organization)

        # create a team and give that team permission to inv1
        team1 = permission_registry.team_model.objects.create(name='team1', organization=organization)
        inv1_or = inv_rd.give_permission(team1, inv1)
        # user still is not a member of team and does not have permission yet
        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set()  # sanity

        # assure user gets permission to that team that existed before getting the org member_team permission
        member_or = member_rd.give_permission(rando, organization)
        assert set(member_or.provides_teams.all()) == set([team1])
        assert set(member_or.descendent_roles()) == set([inv1_or])
        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([inv1])

        # assure user gets permission to a team that is created after getting the org member_team permission
        team2 = permission_registry.team_model.objects.create(name='team2', organization=organization)
        assert set(member_or.provides_teams.all()) == set([team1, team2])
        inv2_or = inv_rd.give_permission(team2, inv2)  # give the new team inventory object-based permission
        assert set(member_or.descendent_roles()) == set([inv1_or, inv2_or])
        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([inv1, inv2])

        # make sure these are also revokable on the member level, both inventories at same time
        member_rd.remove_permission(rando, organization)
        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([])

    @pytest.mark.parametrize('order', ['role_first', 'obj_first'])
    def test_team_assignment_to_organization(self, rando, member_rd, inv_rd, order):
        inv_org = Organization.objects.create(name='inv-org')
        team_org = Organization.objects.create(name='team-org')
        inventory = Inventory.objects.create(name='inv1', organization=inv_org)

        team = permission_registry.team_model.objects.create(name='test-team', organization=team_org)

        if order == 'role_first':
            member_or = member_rd.give_permission(rando, team.organization)
            # This is similar in effect to the old "inventory_admin_role" for organizations
            inv_or = inv_rd.give_permission(team, inventory.organization)
        else:
            inv_or = inv_rd.give_permission(team, inventory.organization)
            member_or = member_rd.give_permission(rando, team.organization)

        assert set(member_or.provides_teams.all()) == set([team])
        assert set(member_or.descendent_roles()) == set([inv_or])

        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([inventory])

        # Now create a new inventory in that organization and make sure permissions still apply
        inv2 = Inventory.objects.create(name='inv2', organization=inventory.organization)
        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([inventory, inv2])

        # now make these those permissions can be revoked by revoking team permission
        member_rd.remove_permission(rando, team.organization)
        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([])

    @pytest.mark.parametrize('order', ['role_first', 'obj_first'])
    def test_team_team_permission_via_org(self, rando, member_rd, inv_rd, order):
        """
        NOTE: this was never supported in AWX, meaning teams could not have organization admin_role
        """
        parent_team = permission_registry.team_model.objects.create(name='parent-team', organization=Organization.objects.create(name='parent'))
        child_team = permission_registry.team_model.objects.create(name='child-team', organization=Organization.objects.create(name='child'))
        inv = Inventory.objects.create(name='inv', organization=child_team.organization)
        assert not rando.has_obj_perm(inv, 'change')

        member_rd.give_permission(rando, parent_team)

        if order == 'role_first':
            member_rd.give_permission(parent_team, child_team.organization)
            assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([])
            inv_rd.give_permission(child_team, inv)
        else:
            inv_rd.give_permission(child_team, inv)
            assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([])
            member_rd.give_permission(parent_team, child_team.organization)

        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([inv])

        # assure permission can be revoked, only 1 link needs to be removed
        if order == 'role_first':
            member_rd.remove_permission(parent_team, child_team.organization)
        else:
            inv_rd.remove_permission(child_team, inv)

        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([])

    def test_team_member_to_own_org(self, rando, organization, inventory, member_rd):
        assert set(RoleEvaluation.accessible_objects(permission_registry.team_model, rando, 'view')) == set([])

        team = permission_registry.team_model.objects.create(name='example-team', organization=organization)
        team_or = member_rd.give_permission(rando, team)
        assert list(team_or.provides_teams.all()) == [team]
        assert set(RoleEvaluation.accessible_objects(Organization, rando, 'view_organization')) == set([])
        assert set(RoleEvaluation.accessible_objects(permission_registry.team_model, rando, 'view_team')) == set([team])

        # this organization role will give permission to view inventories and to be a member of all teams in the org
        team_perms = list(member_rd.permissions.values_list('codename', flat=True))
        org_inv_team_rd = RoleDefinition.objects.create_from_permissions(
            permissions=team_perms + ['view_organization', 'view_inventory'], name='org-multi-permission'
        )
        org_or = org_inv_team_rd.give_permission(team, organization)
        assert list(org_or.provides_teams.all()) == [team]
        assert set(RoleEvaluation.accessible_objects(Organization, rando, 'view_organization')) == set([organization])
        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'view_inventory')) == set([inventory])

        # confirm revoking the user membership removes all those permissions
        member_rd.remove_permission(rando, team)
        assert set(RoleEvaluation.accessible_objects(Organization, rando, 'view_organization')) == set([])
        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'view_inventory')) == set([])


@pytest.mark.django_db
class TestProhibitedAssignments:
    @override_settings(ROLE_TEAM_TEAM_ALLOWED=False)
    def test_team_team_assignment(self, member_rd, organization):
        teamA = permission_registry.team_model.objects.create(name='teamA', organization=organization)
        teamB = permission_registry.team_model.objects.create(name='teamB', organization=organization)
        with pytest.raises(ValidationError) as exc:
            member_rd.give_permission(teamA, teamB)
        assert 'Assigning team permissions to other teams is not allowed' in str(exc)

    @override_settings(ROLE_TEAM_ORG_ALLOWED=False)
    def test_team_org_assignment(self, organization):
        team = permission_registry.team_model.objects.create(name='example-team', organization=organization)
        view_rd = RoleDefinition.objects.create_from_permissions(permissions=['view_organization'], name='view-org')
        with pytest.raises(ValidationError) as exc:
            view_rd.give_permission(team, organization)
        assert 'Assigning organization permissions to teams is not allowed' in str(exc)

    @override_settings(ROLE_TEAM_ORG_TEAM_ALLOWED=False)
    def test_team_org_member_assignment(self, member_rd, organization):
        team = permission_registry.team_model.objects.create(name='example-team', organization=organization)
        with pytest.raises(ValidationError) as exc:
            member_rd.give_permission(team, organization)
        assert 'Assigning organization permissions to teams is not allowed' in str(exc)
