import pytest

from ansible_base.rbac.models import RoleDefinition
from test_app.models import Inventory


@pytest.fixture
def global_inv_rd():
    return RoleDefinition.objects.create_from_permissions(
        permissions=['change_inventory', 'view_inventory'],
        name='global-change-inv',
        content_type=None,
    )


@pytest.mark.django_db
def test_user_singleton_role(rando, inventory, global_inv_rd):
    global_inv_rd.give_global_permission(rando)
    assert rando.has_obj_perm(inventory, 'change_inventory')
    assert rando.singleton_permissions() == {'change_inventory', 'view_inventory'}
    assert list(Inventory.access_qs(rando, 'change')) == [inventory]

    global_inv_rd.remove_global_permission(rando)
    assert not rando.has_obj_perm(inventory, 'change_inventory')
    assert rando.singleton_permissions() == set()
    assert list(Inventory.access_qs(rando, 'change')) == []


@pytest.mark.django_db
def test_singleton_role_via_team(rando, organization, team, inventory, global_inv_rd, member_rd):
    assignment = member_rd.give_permission(rando, organization)
    assert list(assignment.object_role.provides_teams.all()) == [team]

    global_inv_rd.give_global_permission(team)
    assert rando.has_obj_perm(inventory, 'change_inventory')
    assert rando.singleton_permissions() == {'change_inventory', 'view_inventory'}
    assert list(Inventory.access_qs(rando, 'change')) == [inventory]

    global_inv_rd.remove_global_permission(team)
    assert not rando.has_obj_perm(inventory, 'change_inventory')
    assert rando.singleton_permissions() == set()
    assert list(Inventory.access_qs(rando, 'change')) == []
