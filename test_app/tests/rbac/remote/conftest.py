import pytest

from ansible_base.rbac import permission_registry
from ansible_base.rbac.models import DABPermission, RoleDefinition
from test_app.models import Organization


@pytest.fixture
def foo_type():
    "Idea is that this is a remote type, in this case, the foo type"
    org_ct = permission_registry.content_type_model.objects.get_for_model(Organization)
    return permission_registry.content_type_model.objects.create(service='foo', model='foo', app_label='foo', parent_content_type=org_ct)


@pytest.fixture
def foo_permission(foo_type):
    return DABPermission.objects.create(codename='foo_foo', content_type=foo_type)


@pytest.fixture
def foo_rd(foo_type, foo_permission):
    return RoleDefinition.objects.create_from_permissions(
        name='Foo fooers for the foos in foo service', permissions=[foo_permission.api_slug], content_type=foo_type
    )


@pytest.fixture
def foo_type_uuid():
    return permission_registry.content_type_model.objects.create(service='foo', model='foo_uuid', app_label='foo', pk_field_type='uuid')


@pytest.fixture
def foo_permission_uuid(foo_type_uuid):
    return DABPermission.objects.create(codename='foo_foo_uuid', content_type=foo_type_uuid)


@pytest.fixture
def foo_rd_uuid(foo_type_uuid, foo_permission_uuid):
    return RoleDefinition.objects.create_from_permissions(name='UUID foo role thing', permissions=[foo_permission_uuid.api_slug], content_type=foo_type_uuid)
