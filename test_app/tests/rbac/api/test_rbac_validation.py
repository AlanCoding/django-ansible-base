import pytest
from django.db.utils import IntegrityError
from django.urls import reverse

from ansible_base.rbac.models import RoleDefinition


@pytest.mark.django_db
@pytest.mark.parametrize("method", ['delete', 'patch'])
def test_cannot_modify_managed_role_definition(admin_api_client, method):
    rd = RoleDefinition.objects.create(name='foo role', managed=True)
    url = reverse('roledefinition-detail', kwargs={'pk': rd.pk})
    if method == 'delete':
        response = admin_api_client.delete(url)
    else:
        response = admin_api_client.patch(url, data={'description': 'foo'})
    assert response.status_code == 400, response.data
    assert 'Role is managed by the system' in str(response.data)


@pytest.mark.django_db
def test_assignments_are_immutable(admin_api_client, rando, inventory, inv_rd):
    assignment = inv_rd.give_permission(rando, inventory)
    url = reverse('roleuserassignment-detail', kwargs={'pk': assignment.pk})
    response = admin_api_client.patch(url, data={'object_id': 2})
    assert response.status_code == 405


@pytest.mark.django_db
def test_permission_does_not_exist(admin_api_client):
    url = reverse('roledefinition-list')
    response = admin_api_client.post(url, data={'name': 'foo', 'permissions': ['foo.foo_foooo'], 'content_type': 'local.inventory'})
    assert response.status_code == 400


@pytest.mark.django_db
def test_using_permission_for_wrong_model(admin_api_client):
    url = reverse('roledefinition-list')
    response = admin_api_client.post(url, data={'name': 'foo', 'permissions': ['local.view_inventory'], 'content_type': 'local.namespace'})
    assert response.status_code == 400
    assert 'view_inventory is not valid for content type' in str(response.data)


# NOTE: testing a null content_type seems to have a problem with render of admin_api_client
# this does not seem to be a problem when testing with a live server


@pytest.mark.django_db
def test_no_double_assignment(admin_api_client, rando, inventory, inv_rd):
    url = reverse('roleuserassignment-list')
    response = admin_api_client.post(url, data={'object_id': inventory.id, 'user': rando.id, 'role_definition': inv_rd.id})
    assert response.status_code == 201
    with pytest.raises(IntegrityError):
        # processing is assumed to be done on the app side, at least it is for AWX
        response = admin_api_client.post(url, data={'object_id': inventory.id, 'user': rando.id, 'role_definition': inv_rd.id})
