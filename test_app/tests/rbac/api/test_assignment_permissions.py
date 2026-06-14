import pytest
from django.test.utils import override_settings

from ansible_base.lib.utils.response import get_relative_url
from ansible_base.rbac import permission_registry
from ansible_base.rbac.models import RoleDefinition
from test_app.models import ImmutableTask, Inventory, Organization, ResourceWithAdminPerm


@pytest.fixture
def task_admin_rd():
    return RoleDefinition.objects.create_from_permissions(
        permissions=['view_immutabletask', 'delete_immutabletask', 'cancel_immutabletask'],
        name='Task Admin',
        content_type=permission_registry.content_type_model.objects.get_for_model(ImmutableTask),
    )


@pytest.fixture
def task_view_rd():
    return RoleDefinition.objects.create_from_permissions(
        permissions=['view_immutabletask'],
        name='Task View',
        content_type=permission_registry.content_type_model.objects.get_for_model(ImmutableTask),
    )


@pytest.mark.django_db
def test_create_user_assignment_immutable(user_api_client, user, rando, task_admin_rd, task_view_rd, org_admin_rd, organization):
    task = ImmutableTask.objects.create()
    org_admin_rd.give_permission(user, organization)  # setup so that user can see rando
    url = get_relative_url('roleuserassignment-list')
    request_data = {"user": rando.pk, "role_definition": task_admin_rd.pk, "object_id": task.pk}

    response = user_api_client.post(url, data=request_data)
    assert response.status_code == 400, response.data
    assert 'object does not exist' in response.data['object_id'][0]

    task_view_rd.give_permission(user, task)
    response = user_api_client.post(url, data=request_data)
    assert response.status_code == 403, response.data
    # Test custom error message
    assert 'You do not have cancel_immutabletask permission' in str(response.data)

    task_admin_rd.give_permission(user, task)
    response = user_api_client.post(url, data=request_data)
    assert response.status_code == 201, response.data


@pytest.mark.django_db
def test_remove_user_assignment_immutable(user_api_client, user, rando, task_admin_rd, task_view_rd):
    task = ImmutableTask.objects.create()
    assignment = task_admin_rd.give_permission(rando, task)
    url = get_relative_url('roleuserassignment-detail', kwargs={'pk': assignment.pk})

    response = user_api_client.delete(url)
    assert response.status_code == 404, response.data

    task_view_rd.give_permission(user, task)
    response = user_api_client.delete(url)
    assert response.status_code == 403, response.data
    # Test custom error message
    assert 'You do not have cancel_immutabletask permission' in str(response.data)

    task_admin_rd.give_permission(user, task)
    response = user_api_client.delete(url)
    assert response.status_code == 204, response.data

    assert not type(assignment).objects.filter(pk=assignment.pk).exists()


@pytest.mark.django_db
def test_remove_user_assignment_with_global_role(user_api_client, user, inv_rd, global_inv_rd, rando, inventory):
    assignment = inv_rd.give_permission(rando, inventory)
    url = get_relative_url('roleuserassignment-detail', kwargs={'pk': assignment.pk})
    response = user_api_client.delete(url)
    assert response.status_code == 404, response.data

    global_inv_rd.give_global_permission(user)
    response = user_api_client.delete(url)
    assert response.status_code == 204, response.data

    assert not type(assignment).objects.filter(pk=assignment.pk).exists()


@pytest.mark.django_db
def test_remove_global_role_assignment(user_api_client, admin_api_client, user, global_inv_rd, rando):
    assignment = global_inv_rd.give_global_permission(rando)
    url = get_relative_url('roleuserassignment-detail', kwargs={'pk': assignment.pk})
    response = user_api_client.delete(url)
    assert response.status_code == 404, response.data

    # Having the role itself does not give permission to remove assignments, but this user can view
    global_inv_rd.give_global_permission(user)
    response = user_api_client.delete(url)
    assert response.status_code == 403, response.data

    # Only superuser can remove global assignments
    response = admin_api_client.delete(url)
    assert response.status_code == 204, response.data

    assert not type(assignment).objects.filter(pk=assignment.pk).exists()


@pytest.mark.django_db
def test_remove_global_assignment_yourself(user_api_client, global_inv_rd, user, inventory):
    assert not user.has_obj_perm(inventory, 'change')

    assignment = global_inv_rd.give_global_permission(user)
    assert user.has_obj_perm(inventory, 'change')

    url = get_relative_url('roleuserassignment-detail', kwargs={'pk': assignment.pk})
    response = user_api_client.delete(url)
    # Manually delete cache, because view operates on a User instance loaded anew from DB
    delattr(user, '_singleton_permissions')
    assert response.status_code == 204, response.data
    assert not user.has_obj_perm(inventory, 'change')


@pytest.mark.django_db
def test_remove_object_assignment_yourself(user_api_client, user, inventory):
    assert not user.has_obj_perm(inventory, 'view')

    rd = RoleDefinition.objects.create_from_permissions(
        name='inventory viewer role', permissions=['view_inventory'], content_type=permission_registry.content_type_model.objects.get_for_model(inventory)
    )
    assignment = rd.give_permission(user, inventory)
    assert user.has_obj_perm(inventory, 'view')

    url = get_relative_url('roleuserassignment-detail', kwargs={'pk': assignment.pk})
    response = user_api_client.delete(url)
    assert response.status_code == 204, response.data
    assert not user.has_obj_perm(inventory, 'change')


@pytest.mark.django_db
class TestManagePermissionAction:
    """Tests for ANSIBLE_BASE_MANAGE_PERMISSION_ACTION controlling who can assign roles"""

    def test_change_user_can_assign_default(self, user_api_client, user, rando, inv_rd, org_admin_rd, organization):
        """With default setting ('change'), user with change permission can assign roles"""
        org_admin_rd.give_permission(user, organization)
        inv_rd.give_permission(user, Inventory.objects.create(name='test-inv', organization=organization))
        inv = Inventory.objects.create(name='target-inv', organization=organization)
        inv_rd.give_permission(user, inv)

        url = get_relative_url('roleuserassignment-list')
        view_rd = RoleDefinition.objects.create_from_permissions(
            name='view-inv', permissions=['view_inventory'], content_type=permission_registry.content_type_model.objects.get_for_model(Inventory)
        )
        response = user_api_client.post(url, data={'user': rando.pk, 'role_definition': view_rd.pk, 'object_id': inv.pk})
        assert response.status_code == 201, response.data

    @override_settings(ANSIBLE_BASE_MANAGE_PERMISSION_ACTION=None)
    def test_all_permissions_required_when_setting_none(self, user_api_client, user, rando, org_admin_rd, organization):
        """With setting=None, user needs ALL permissions to assign roles"""
        org_admin_rd.give_permission(user, organization)
        other_org = Organization.objects.create(name='other-org')
        inv = Inventory.objects.create(name='target-inv', organization=other_org)

        view_rd = RoleDefinition.objects.create_from_permissions(
            name='view-inv', permissions=['view_inventory'], content_type=permission_registry.content_type_model.objects.get_for_model(Inventory)
        )
        # Give user only view — not enough when all permissions required
        view_rd.give_permission(user, inv)
        url = get_relative_url('roleuserassignment-list')
        response = user_api_client.post(url, data={'user': rando.pk, 'role_definition': view_rd.pk, 'object_id': inv.pk})
        assert response.status_code == 403, response.data

        # Give user all permissions — now assignment succeeds
        all_rd = RoleDefinition.objects.create_from_permissions(
            name='all-inv',
            permissions=['change_inventory', 'delete_inventory', 'view_inventory', 'update_inventory'],
            content_type=permission_registry.content_type_model.objects.get_for_model(Inventory),
        )
        all_rd.give_permission(user, inv)
        response = user_api_client.post(url, data={'user': rando.pk, 'role_definition': view_rd.pk, 'object_id': inv.pk})
        assert response.status_code == 201, response.data

    @override_settings(ANSIBLE_BASE_MANAGE_PERMISSION_ACTION='administrate')
    def test_administrate_action_controls_assignment(self, user_api_client, user, rando, org_admin_rd, organization):
        """With setting='administrate', only users with 'administrate' permission can assign roles"""
        org_admin_rd.give_permission(user, organization)
        other_org = Organization.objects.create(name='other-org')
        resource = ResourceWithAdminPerm.objects.create(name='test-resource', organization=other_org)

        admin_perm_rd = RoleDefinition.objects.create_from_permissions(
            name='admin-resource',
            permissions=[
                'administrate_resourcewithadminperm',
                'change_resourcewithadminperm',
                'delete_resourcewithadminperm',
                'view_resourcewithadminperm',
            ],
            content_type=permission_registry.content_type_model.objects.get_for_model(ResourceWithAdminPerm),
        )
        change_rd = RoleDefinition.objects.create_from_permissions(
            name='change-resource',
            permissions=['change_resourcewithadminperm', 'view_resourcewithadminperm'],
            content_type=permission_registry.content_type_model.objects.get_for_model(ResourceWithAdminPerm),
        )
        view_rd = RoleDefinition.objects.create_from_permissions(
            name='view-resource',
            permissions=['view_resourcewithadminperm'],
            content_type=permission_registry.content_type_model.objects.get_for_model(ResourceWithAdminPerm),
        )

        # User with change but NOT administrate cannot assign roles
        change_rd.give_permission(user, resource)
        url = get_relative_url('roleuserassignment-list')
        response = user_api_client.post(url, data={'user': rando.pk, 'role_definition': view_rd.pk, 'object_id': resource.pk})
        assert response.status_code == 403, response.data

        # User with administrate CAN assign roles
        admin_perm_rd.give_permission(user, resource)
        response = user_api_client.post(url, data={'user': rando.pk, 'role_definition': view_rd.pk, 'object_id': resource.pk})
        assert response.status_code == 201, response.data

    @override_settings(ANSIBLE_BASE_MANAGE_PERMISSION_ACTION='administrate')
    def test_model_without_manage_action_requires_all(self, user_api_client, user, rando, org_admin_rd, organization):
        """Models without the configured manage action fall back to requiring all permissions"""
        org_admin_rd.give_permission(user, organization)
        other_org = Organization.objects.create(name='other-org')
        inv = Inventory.objects.create(name='target-inv', organization=other_org)

        change_rd = RoleDefinition.objects.create_from_permissions(
            name='change-inv',
            permissions=['change_inventory', 'view_inventory'],
            content_type=permission_registry.content_type_model.objects.get_for_model(Inventory),
        )
        view_rd = RoleDefinition.objects.create_from_permissions(
            name='view-inv',
            permissions=['view_inventory'],
            content_type=permission_registry.content_type_model.objects.get_for_model(Inventory),
        )

        # Inventory has no 'administrate' permission, so falls back to "all permissions required"
        # User with change only cannot assign
        change_rd.give_permission(user, inv)
        url = get_relative_url('roleuserassignment-list')
        response = user_api_client.post(url, data={'user': rando.pk, 'role_definition': view_rd.pk, 'object_id': inv.pk})
        assert response.status_code == 403, response.data
