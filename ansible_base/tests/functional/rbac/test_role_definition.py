import pytest
from django.core.exceptions import ValidationError

from ansible_base.models.rbac import RoleDefinition


@pytest.mark.django_db
def test_reuse_by_permission_list():
    demo_permissions = ['view_inventory', 'delete_inventory']
    rd1, created = RoleDefinition.objects.get_or_create(permissions=demo_permissions, name='test-deleter')
    assert created

    # Will ignore name in favor of permissions
    rd2, created = RoleDefinition.objects.get_or_create(permissions=demo_permissions, name='test-deleter-two')
    assert (not created) and (rd2 == rd1)


@pytest.mark.django_db
def test_missing_use_permission():
    with pytest.raises(ValidationError) as exc:
        RoleDefinition.objects.create_from_permissions(permissions=['change_organization'], name='only-change-org')
    assert 'needs to include view' in str(exc)


@pytest.mark.django_db
def test_permission_for_unregistered_model():
    with pytest.raises(ValidationError):
        RoleDefinition.objects.create_from_permissions(permissions=['view_exampleevent'], name='not-cool')
