import pytest
from django.contrib.contenttypes.models import ContentType
from django.urls import reverse

from ansible_base.rbac.models import ObjectRole, RoleEvaluation
from ansible_base.resource_registry.models import Resource


@pytest.mark.django_db
def test_user_assignment_ansible_id(admin_api_client, inv_rd, rando, inventory):
    resource = Resource.objects.get(object_id=rando.pk, content_type=ContentType.objects.get_for_model(rando).pk)
    url = reverse('roleuserassignment-list')
    data = dict(role_definition=inv_rd.id, content_type='local.inventory', user_ansible_id=str(resource.ansible_id), object_id=inventory.id)
    response = admin_api_client.post(url, data=data, format="json")
    assert response.status_code == 201, response.data
    assert rando.has_obj_perm(inventory, 'change')


@pytest.mark.django_db
def test_team_assignment_ansible_id(admin_api_client, inv_rd, team, inventory, member_rd, rando):
    member_rd.give_permission(rando, team)
    team_ct = ContentType.objects.get_for_model(team)
    resource = Resource.objects.get(object_id=team.pk, content_type=team_ct.pk)
    url = reverse('roleteamassignment-list')
    data = dict(role_definition=inv_rd.id, content_type='local.inventory', team_ansible_id=str(resource.ansible_id), object_id=inventory.id)
    response = admin_api_client.post(url, data=data, format="json")
    assert response.status_code == 201, response.data

    team_role = ObjectRole.objects.get(object_id=team.id, content_type=team_ct, role_definition=member_rd)
    assert RoleEvaluation.objects.filter(role=team_role, codename='change_inventory', object_id=inventory.id).count() == 1
    assert rando.has_obj_perm(inventory, 'change')
