import pytest

from ansible_base.lib.utils.response import get_relative_url


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
