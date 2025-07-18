from copy import deepcopy

import pytest

from ansible_base.lib.utils.response import get_relative_url
from ansible_base.rbac.models import DABContentType, DABPermission


@pytest.mark.django_db
def test_get_resource_list(admin_api_client):
    url = get_relative_url('dabcontenttype-list')
    response = admin_api_client.get(url, format="json")
    assert response.status_code == 200, response.data
    type_data = {t['api_slug']: t for t in response.data['results']}

    assert 'shared.organization' in type_data
    org_data = type_data['shared.organization']
    assert org_data['parent_content_type'] is None
    assert org_data['service'] == 'shared'
    assert org_data['model'] == 'organization'

    assert 'aap.inventory' in type_data
    inv_data = type_data['aap.inventory']
    assert inv_data['parent_content_type'] == 'shared.organization'


@pytest.mark.django_db
def test_get_permission_list(admin_api_client):
    url = get_relative_url('dabpermission-list')
    response = admin_api_client.get(url + '?page_size=200', format="json")
    assert response.status_code == 200, response.data
    type_data = {t['api_slug']: t for t in response.data['results']}

    assert 'shared.change_organization' in type_data
    change_org_data = type_data['shared.change_organization']
    assert change_org_data['content_type'] == 'shared.organization'
    assert change_org_data['codename'] == 'change_organization'


@pytest.mark.django_db
def test_role_definition_listed_as_resource(admin_api_client, org_admin_rd):
    url = get_relative_url('resource-list')
    url += '?page_size=200&content_type__resource_type__name=shared.roledefinition'
    response = admin_api_client.get(url, format="json")
    assert response.status_code == 200, response.data
    rd_data = {rd['name']: rd for rd in response.data['results']}

    assert 'Organization Admin' in rd_data
    org_admin_data = rd_data['Organization Admin']

    detail = admin_api_client.get(org_admin_data['url'], format="json")
    assert detail.status_code == 200, detail.data
    resource_data = detail.data['resource_data']
    assert resource_data['managed'] is True
    assert resource_data['content_type'] == 'shared.organization'
    assert 'permissions' in detail.data['resource_data']
    assert 'aap.add_inventory' in detail.data['resource_data']['permissions']


@pytest.mark.django_db
def test_reload_types(admin_api_client):
    url = get_relative_url('dabcontenttype-list')
    response = admin_api_client.get(url + '?page_size=200', format="json")
    assert response.status_code == 200, response.data

    type_list = response.data['results']
    original = deepcopy(type_list)

    DABContentType.objects.all().delete()  # Delete all types, see if we get them back

    DABContentType.objects.load_remote_types(type_list)

    response = admin_api_client.get(url + '?page_size=200', format="json")
    assert response.status_code == 200, response.data

    assert response.data['results'] == original


@pytest.mark.django_db
def test_load_child_of_org():
    DABContentType.objects.load_remote_types([{'service': 'fooland', 'app_label': 'foop', 'model': 'fooser', 'parent_content_type': 'shared.organization'}])
    ct = DABContentType.objects.get(api_slug='fooland.fooser')
    assert ct.parent_content_type.app_label == 'test_app'  # proves connection to existing


@pytest.mark.django_db
def test_reload_permissions(admin_api_client):
    url = get_relative_url('dabpermission-list')
    response = admin_api_client.get(url + '?page_size=200', format="json")
    assert response.status_code == 200, response.data

    perm_list = response.data['results']
    original = deepcopy(perm_list)

    DABPermission.objects.all().delete()  # Delete all permissions, see if we get them back

    DABPermission.objects.load_remote_types(perm_list)

    response = admin_api_client.get(url + '?page_size=200', format="json")
    assert response.status_code == 200, response.data

    assert response.data['results'] == original


@pytest.mark.django_db
def test_list_role_user_assignments(admin_api_client, rando, inv_rd, inventory):
    inv_rd.give_permission(rando, inventory)

    url = get_relative_url('serviceuserassignment-list')
    response = admin_api_client.get(url + '?page_size=200', format="json")
    assert response.status_code == 200, response.data

    candidates = [assignment for assignment in response.data['results'] if assignment['role_definition'] == inv_rd.name]
    assert len(candidates) == 1, response.data
    from_api = candidates[0]

    assert int(from_api['object_id']) == inventory.id
    assert from_api['user_ansible_id'] == str(rando.resource.ansible_id)
    assert from_api['content_type'] == 'aap.inventory'


@pytest.mark.django_db
def test_apply_role_assignment(admin_api_client, rando, inv_rd, inventory):
    url = get_relative_url('serviceuserassignment-assign')

    data = {"role_definition": inv_rd.name, "user_ansible_id": str(rando.resource.ansible_id), "object_id": inventory.pk}

    assert not rando.has_obj_perm(inventory, 'change')
    response = admin_api_client.post(url, data=data)
    assert response.status_code == 201, response.data
    assert rando.has_obj_perm(inventory, 'change')

    # Second try, response code indicates assignment already exists
    response = admin_api_client.post(url, data=data)
    assert response.status_code == 200, response.data


@pytest.mark.django_db
def test_unassign_endpoint(rando, org_inv_rd, inventory, admin_api_client):
    org_inv_rd.give_permission(rando, inventory.organization)
    assert rando.has_obj_perm(inventory, 'change')

    url = get_relative_url('serviceuserassignment-unassign')
    data = {
        "role_definition": org_inv_rd.name,
        "user_ansible_id": str(rando.resource.ansible_id),
        "object_ansible_id": str(inventory.organization.resource.ansible_id),
    }
    response = admin_api_client.post(url, data)
    assert response.status_code == 204, response.data
    assert not rando.has_obj_perm(inventory, 'change')

    # second gets a 200 code
    response = admin_api_client.post(url, data)
    assert response.status_code == 200, response.data
    assert not rando.has_obj_perm(inventory, 'change')


# teams
@pytest.mark.django_db
def test_apply_role_assignment_for_team(admin_api_client, inv_rd, inventory, team, member_rd, rando):
    member_rd.give_permission(rando, team)
    url = get_relative_url('serviceteamassignment-assign')

    data = {"role_definition": inv_rd.name, "team_ansible_id": str(team.resource.ansible_id), "object_id": inventory.pk}

    assert not rando.has_obj_perm(inventory, 'change')
    response = admin_api_client.post(url, data=data)
    assert response.status_code == 201, response.data
    assert rando.has_obj_perm(inventory, 'change')

    # Second try, response code indicates assignment already exists
    response = admin_api_client.post(url, data=data)
    assert response.status_code == 200, response.data


@pytest.mark.django_db
def test_unassign_endpoint_for_team(team, org_inv_rd, inventory, admin_api_client, member_rd, rando):
    member_rd.give_permission(rando, team)
    org_inv_rd.give_permission(team, inventory.organization)
    assert rando.has_obj_perm(inventory, 'change')

    url = get_relative_url('serviceteamassignment-unassign')
    data = {
        "role_definition": org_inv_rd.name,
        "team_ansible_id": str(team.resource.ansible_id),
        "object_ansible_id": str(inventory.organization.resource.ansible_id),
    }
    response = admin_api_client.post(url, data)
    assert response.status_code == 204, response.data
    assert not rando.has_obj_perm(inventory, 'change')

    # second gets a 200 code
    response = admin_api_client.post(url, data)
    assert response.status_code == 200, response.data
    assert not rando.has_obj_perm(inventory, 'change')


@pytest.mark.django_db
def test_filter_assignment_list(admin_api_client, rando, inv_rd, view_inv_rd, org_inv_rd, inventory):
    inv_rd.give_permission(rando, inventory)
    org_inv_rd.give_permission(rando, inventory.organization)
    view_inv_rd.give_permission(rando, inventory)

    url = get_relative_url('serviceuserassignment-list')
    response = admin_api_client.get(url + f'?user={rando.id}', format="json")
    assert response.status_code == 200, response.data
    assert response.data['count'] == 3  # user rando has 3 rol assignments

    # Get just one single assignment
    response = admin_api_client.get(url + f'?assignment={str(rando.resource.ansible_id)},{inv_rd.name},{inventory.id}', format="json")
    assert response.status_code == 200, response.data
    assert response.data['count'] == 1
    assert response.data['results'][0]['role_definition'] == inv_rd.name

    # Assure we can get two assignments at the same time
    response = admin_api_client.get(
        url
        + (
            f'?assignment={str(rando.resource.ansible_id)},{inv_rd.name},{inventory.id}&'
            f'assignment={str(rando.resource.ansible_id)},{org_inv_rd.name},{inventory.organization.id}'
        ),
        format="json",
    )
    assert response.status_code == 200, response.data
    assert response.data['count'] == 2


@pytest.mark.django_db
@pytest.mark.parametrize(
    'reverse_name,normal_case,unauth_case',
    [
        ('dabcontenttype-list', 200, 401),  # could change unauthenticated case, depends on need
        ('dabpermission-list', 200, 401),
        ('resource-list', 403, 401),
        ('serviceuserassignment-list', 403, 401),
        ('serviceteamassignment-list', 403, 401),
    ],
)
def test_service_api_permissions(reverse_name, normal_case, unauth_case, admin_api_client, user_api_client, unauthenticated_api_client):
    url = get_relative_url(reverse_name)

    admin_response = admin_api_client.get(url)
    assert admin_response.status_code == 200, admin_response.data

    normal_response = user_api_client.get(url)
    assert normal_response.status_code == normal_case, normal_response.data

    unauth_response = unauthenticated_api_client.get(url)
    assert unauth_response.status_code == unauth_case, unauth_response.data
