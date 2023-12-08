import pytest
from django.contrib.auth.models import Permission

from ansible_base.models.rbac import RoleDefinition, RoleEvaluation
from ansible_base.rbac.permission_registry import permission_registry
from ansible_base.tests.functional.models import Inventory, Organization


@pytest.fixture
def team(organization):
    return permission_registry.team_model.objects.create(name='example-team-or-group', organization=organization)


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
    @pytest.fixture
    def member_rd(self):
        return RoleDefinition.objects.create_from_permissions(
            permissions=[permission_registry.team_permission, f'view_{permission_registry.team_model._meta.model_name}'], name='team-member'
        )

    @pytest.fixture
    def inv_rd(self):
        return RoleDefinition.objects.create_from_permissions(permissions=['change_inventory', 'view_inventory'], name='change-inv')

    def test_object_team_assignment(self, rando, inventory, team, member_rd, inv_rd):
        member_or = member_rd.give_permission(rando, team)
        assert set(member_or.provides_teams.all()) == set([team])
        inv_or = inv_rd.give_permission(team, inventory)
        assert team in inv_or.teams.all()

        assert set(RoleEvaluation.accessible_objects(Inventory, rando, 'change_inventory')) == set([inventory])

    def test_organization_team_assignment(self, rando, organization, member_rd, inv_rd):
        assert Permission.objects.filter(codename='member_team').exists()  # sanity
        inv1 = Inventory.objects.create(name='inv1', organization=organization)
        inv2 = Inventory.objects.create(name='inv2', organization=organization)

        # create a team and give that team permission to an inventory object
        team1 = permission_registry.team_model.objects.create(name='team1', organization=organization)
        inv1_or = inv_rd.give_permission(team1, inv1)
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
