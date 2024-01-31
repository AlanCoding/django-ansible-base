import pytest
from django.urls import reverse

from ansible_base.rbac.models import RoleDefinition, UserAssignment


@pytest.mark.django_db
def test_get_role_definition(admin_api_client, inv_rd):
    url = reverse('roledefinition-detail', kwargs={'pk': inv_rd.pk})
    response = admin_api_client.get(url)
    assert response.status_code == 200
    assert set(response.data['permissions']) == set(['local.change_inventory', 'local.view_inventory'])


@pytest.mark.django_db
def test_create_role_definition(admin_api_client):
    """
    Test creation of a custom role definition.
    """
    url = reverse("roledefinition-list")
    data = dict(name='foo-role-def', description='bar', permissions=['local.view_organization', 'local.change_organization'])
    response = admin_api_client.post(url, data=data, format="json")
    assert response.status_code == 201, response.data
    assert response.data['name'] == 'foo-role-def'


@pytest.mark.django_db
def test_delete_role_definition(admin_api_client, inv_rd):
    url = reverse('roledefinition-detail', kwargs={'pk': inv_rd.pk})
    response = admin_api_client.delete(url)
    assert response.status_code == 204, response.data
    assert not RoleDefinition.objects.filter(pk=inv_rd.pk).exists()


@pytest.mark.django_db
def test_get_user_assignment(admin_api_client, inv_rd, rando, inventory):
    object_role = inv_rd.give_permission(rando, inventory)
    assignment = UserAssignment.objects.get(object_role=object_role, user=rando)
    url = reverse('userassignment-detail', kwargs={'pk': assignment.pk})
    response = admin_api_client.get(url)
    assert response.data['content_type'] == 'local.inventory'
    assert response.data['object_id'] == inventory.id
    assert response.data['role_definition'] == inv_rd.id
    assert not response.data['created_by']  # created by code, not by view


@pytest.mark.django_db
def test_make_user_assignment(admin_api_client, inv_rd, rando, inventory):
    url = reverse('userassignment-list')
    data = dict(role_definition=inv_rd.id, user=rando.id, content_type='local.inventory', object_id=inventory.id)
    response = admin_api_client.post(url, data=data, format="json")
    assert response.status_code == 201, response.data
    assert response.data['created_by']
