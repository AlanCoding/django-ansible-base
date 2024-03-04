import pytest
from django.contrib.contenttypes.models import ContentType
from django.test.utils import override_settings

from ansible_base.rbac.models import RoleDefinition, RoleEvaluation
from test_app.models import User

INVENTORY_OBJ_PERMS = ('change_inventory', 'update_inventory', 'view_inventory', 'delete_inventory')


@pytest.mark.django_db
def test_create_inventory_gain_role(rando, inventory):
    assert set(RoleEvaluation.get_permissions(rando, inventory)) == set()
    RoleDefinition.objects.give_creator_permissions(rando, inventory)
    assert set(perm_name.split('_', 1)[0] for perm_name in RoleEvaluation.get_permissions(rando, inventory)) == {'change', 'delete', 'view'}
    assert RoleDefinition.objects.filter(name='inventory-creator-permission').exists()


@pytest.mark.django_db
def test_create_inventory_already_has_role(rando, inventory):
    org_inv_rd = RoleDefinition.objects.create_from_permissions(
        name='global-inventory-admin', permissions=INVENTORY_OBJ_PERMS, content_type=ContentType.objects.get_for_model(inventory.organization)
    )
    org_assignment = org_inv_rd.give_permission(rando, inventory.organization)
    # User should already have (at least) all object permissions on the inventory
    assert not (set(INVENTORY_OBJ_PERMS) - set(RoleEvaluation.get_permissions(rando, inventory)))
    RoleDefinition.objects.give_creator_permissions(rando, inventory)
    assert set(rando.has_roles.all()) == {org_assignment.object_role}


@pytest.mark.django_db
def test_creator_permissions_for_superuser(inventory):
    admin_user = User.objects.create(is_superuser=True, username='admin')
    RoleDefinition.objects.give_creator_permissions(admin_user, inventory)
    assert not admin_user.has_roles.exists()


@pytest.mark.django_db
def test_no_creator_assignment_with_system_perms(rando, inventory):
    rd = RoleDefinition.objects.create_from_permissions(name='global-inventory-admin', permissions=INVENTORY_OBJ_PERMS)
    rd.give_global_permission(rando)
    RoleDefinition.objects.give_creator_permissions(rando, inventory)
    assert not rando.has_roles.exists()


@pytest.mark.django_db
def test_custom_creation_perms(rando, inventory):
    # these settings would not let users delete what they create
    # which someone might want, you do you
    with override_settings(ANSIBLE_BASE_CREATOR_DEFAULTS=['change', 'view']):
        RoleDefinition.objects.give_creator_permissions(rando, inventory)
        assert set(perm_name.split('_', 1)[0] for perm_name in RoleEvaluation.get_permissions(rando, inventory)) == {'change', 'view'}
