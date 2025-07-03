import pytest

from ansible_base.lib.utils.response import get_relative_url
from ansible_base.rbac.remote import RemoteObject


@pytest.mark.django_db
def test_role_definition_list_remote_and_local(admin_api_client, inv_rd, foo_rd):
    url = get_relative_url('roledefinition-list')
    response = admin_api_client.get(url)
    assert response.status_code == 200
    assert response.data['next'] is None  # sanity, will mess up test if there are more pages
    rd_by_name = {rd['name']: rd for rd in response.data['results']}
    assert inv_rd.name in rd_by_name
    assert foo_rd.name in rd_by_name
    # Assertion coppied from API test test_get_role_definition
    assert set(rd_by_name[inv_rd.name]['permissions']) == set(['aap.change_inventory', 'aap.view_inventory'])
    assert rd_by_name[foo_rd.name]['permissions'] == ['foo.foo_foo']


@pytest.mark.django_db
def test_create_remote_role_definition(admin_api_client, foo_type, foo_permission):
    """
    Test creation of a custom, remote role definition.
    """
    url = get_relative_url("roledefinition-list")
    data = dict(name='foo-foo-foo-custom', description='bar', permissions=[foo_permission.api_slug], content_type=foo_type.api_slug)
    response = admin_api_client.post(url, data=data, format="json")
    assert response.status_code == 201, response.data
    assert response.data['name'] == 'foo-foo-foo-custom'
    assert response.data['permissions'] == ['foo.foo_foo']


@pytest.mark.django_db
def test_give_remote_permission(admin_api_client, rando, foo_type, foo_rd):
    a_foo = RemoteObject(content_type=foo_type, object_id=42)
    assignment = foo_rd.give_permission(rando, a_foo)
    assignment.content_object

    assert isinstance(assignment.content_object, RemoteObject)

    # Should show up in the assignments list
    url = get_relative_url('roleuserassignment-list')
    response = admin_api_client.get(url, format="json")
    assert response.status_code == 200, response.data

    data_by_rd = {item['role_definition']: item for item in response.data['results']}
    assert foo_rd.id in data_by_rd
    item = data_by_rd[foo_rd.id]
    assert item['user'] == rando.id
    assert item['object_id'] == str(a_foo.object_id)
    assert 'summary_fields' in item
    sf = item['summary_fields']
    assert 'content_object' in sf
    assert sf['content_object'] == {'<remote_object_placeholder>': True, 'model_name': 'foo', 'service': 'foo', 'pk': 42}
