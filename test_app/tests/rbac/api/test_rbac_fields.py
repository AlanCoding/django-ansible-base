import pytest
from django.urls import reverse

from ansible_base.rbac.api.serializers import RoleDefinitionSerializer


@pytest.mark.django_db
def test_invalid_content_type(admin_api_client):
    serializer = RoleDefinitionSerializer(
        data=dict(name='foo-role-def', description='bar', permissions=['local.view_organization'], content_type='local.foo_does_not_exist_model')
    )
    assert not serializer.is_valid()
    assert 'object does not exist' in str(serializer.errors['content_type'])
    assert 'permissions' not in serializer.errors


@pytest.mark.django_db
def test_invalid_permission(admin_api_client):
    serializer = RoleDefinitionSerializer(
        data=dict(name='foo-role-def', description='bar', permissions=['local.view_foohomeosi'], content_type='local.organization')
    )
    assert not serializer.is_valid()
    assert 'object does not exist' in str(serializer.errors['permissions'])
    assert 'content_type' not in serializer.errors


@pytest.mark.django_db
def test_parity_with_resource_registry(admin_api_client):
    types_resp = admin_api_client.get(reverse("resourcetype-list"))
    assert types_resp.status_code == 200
    res_types = set(r['name'] for r in types_resp.data['results'])

    role_types = admin_api_client.options(reverse("roledefinition-list"))
    role_types = set(item['value'] for item in role_types.data['actions']['POST']['content_type']['choices'])

    # Check the types in both registries
    for type_name in ('shared.organization', 'shared.team'):
        assert type_name in res_types
        assert type_name in role_types
