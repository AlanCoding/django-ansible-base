import pytest

from ansible_base.lib.utils.response import get_relative_url
from ansible_base.rbac.remote import RemoteObject


@pytest.mark.django_db
def test_user_access_list_remote_obj(admin_api_client, rando, foo_type, foo_rd):
    url = get_relative_url('role-user-access', kwargs={'pk': 42, 'model_name': foo_type.api_slug})

    a_foo = RemoteObject(content_type=foo_type, object_id=42)
    foo_rd.give_permission(rando, a_foo)

    response = admin_api_client.get(url)
    assert response.status_code == 200
    user_data = {}
    for user_detail in response.data['results']:
        user_data[user_detail['username']] = user_detail['role_assignments']

    # User is shown as having direct access to the remote object
    assert rando.username in user_data
    assert len(user_data[rando.username]) == 1
    assert user_data[rando.username][0]['type'] == 'direct'
