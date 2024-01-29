import pytest
from django.urls import reverse

from test_app.models import Inventory, Organization


@pytest.mark.django_db
def test_gain_organization_inventory_view(user_api_client, user, org_inv_rd):
    org = Organization.objects.create(name='foo')
    Inventory.objects.create(name='bar', organization=org)

    r = user_api_client.get(reverse('organization-list'))
    assert r.status_code == 200, r.data
    assert r.data['results'] == []

    r = user_api_client.get(reverse('inventory-list'))
    assert r.status_code == 200, r.data
    assert r.data['results'] == []

    org_inv_rd.give_permission(user, org)

    r = user_api_client.get(reverse('organization-list'))
    assert r.status_code == 200, r.data
    assert len(r.data['results']) == 1

    r = user_api_client.get(reverse('inventory-list'))
    assert r.status_code == 200, r.data
    assert len(r.data['results']) == 1
