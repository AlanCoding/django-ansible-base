import pytest

from ansible_base.lib.utils.response import get_relative_url


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


# TODO: check that assignment endpoint works

# @pytest.mark.django_db
# def test_give_remote_permission(rando, foo_type, foo_permission, foo_rd):
#     assert foo_type.service == 'foo'  # a place, a domain, a server, known as foo
#     assert foo_type.api_slug == 'foo.foo'  # there lives a foo in foo

#     assert foo_permission.api_slug == 'foo.foo_foo'  # expression of the ability that one may foo a foo

#     a_foo = RemoteObject(content_type=foo_type, object_id=42)
#     assignment = foo_rd.give_permission(rando, a_foo)

#     assignment = RoleUserAssignment.objects.get(pk=assignment.pk)
#     assert isinstance(assignment.content_object, RemoteObject)

#     # We can do evaluation querysets, but these can not return objects, just id values
#     assert set(foo_type.model_class().access_ids_qs(actor=rando, codename='foo')) == {(int(assignment.object_id),)}

#     # Test that user-attached methods also work
#     assert rando.has_obj_perm(a_foo, 'foo')
#     with pytest.raises(RuntimeError) as exc:
#         assert not rando.has_obj_perm(a_foo, 'bar')  # not a valid permission
#     assert 'The permission bar_foo is not valid for model foo' in str(exc)
