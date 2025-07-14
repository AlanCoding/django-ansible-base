import pytest

from ansible_base.rbac.models import DABContentType, DABPermission, RoleDefinition


@pytest.fixture
def foo_type():
    "Idea is that this is a remote type, in this case, the foo type"
    return DABContentType.objects.create(service='foo', model='foo', app_label='foo')


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
    return DABContentType.objects.create(service='foo', model='foo_uuid', app_label='foo', pk_field_type='uuid')


@pytest.fixture
def foo_permission_uuid(foo_type_uuid):
    return DABPermission.objects.create(codename='foo_foo_uuid', content_type=foo_type_uuid)


@pytest.fixture
def foo_rd_uuid(foo_type_uuid, foo_permission_uuid):
    return RoleDefinition.objects.create_from_permissions(name='UUID foo role thing', permissions=[foo_permission_uuid.api_slug], content_type=foo_type_uuid)
