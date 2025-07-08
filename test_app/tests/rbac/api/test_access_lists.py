import pytest

from ansible_base.lib.utils.response import get_relative_url

from test_app.models import User, Team


@pytest.mark.django_db
def test_user_access_list(admin_api_client, inv_rd, org_inv_rd, inventory, member_rd):
    url = get_relative_url('role-user-access', kwargs={'pk': inventory.pk, 'model_name': 'aap.inventory'})

    u1 = User.objects.create(username='direct-inv-access')
    inv_rd.give_permission(u1, inventory)

    u2 = User.objects.create(username='org-level-access')
    org_inv_rd.give_permission(u2, inventory.organization)

    u3 = User.objects.create(username='team-via-access')
    team = Team.objects.create(name='proxy-team', organization=inventory.organization)
    inv_rd.give_permission(team, inventory)
    member_rd.give_permission(u3, team)

    response = admin_api_client.get(url)
    assert response.status_code == 200

    user_data = {}
    for user_detail in response.data['results']:
        user_data[user_detail['username']] = user_detail['role_assignments']

    assert u1.username in user_data
    assert len(user_data[u1.username]) == 1
    assert user_data[u1.username][0]['type'] == 'direct'

    assert u2.username in user_data
    assert len(user_data[u2.username]) == 1
    assert user_data[u2.username][0]['type'] == 'indirect'

    assert u3.username in user_data
    assert len(user_data[u3.username]) == 1
    assert user_data[u3.username][0]['type'] == 'team'
