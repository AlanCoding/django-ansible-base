import pytest

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
