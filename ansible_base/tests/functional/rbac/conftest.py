import pytest
from django.contrib.auth import get_user_model

from ansible_base.models.rbac import RoleDefinition
from ansible_base.tests.functional.models import Inventory, Organization


@pytest.fixture
def organization():
    return Organization.objects.create(name='Default')


@pytest.fixture
def inventory(organization):
    return Inventory.objects.create(name='Default-inv', organization=organization)


@pytest.fixture
def rando():
    return get_user_model().objects.create(username='rando')


@pytest.fixture
def org_inv_rd():
    admin_permissions = ['change_organization', 'view_organization', 'change_inventory', 'view_inventory']
    return RoleDefinition.objects.create_from_permissions(permissions=admin_permissions, name='org-admin')
