import pytest

from ansible_base.rbac.models import DABContentType, DABPermission, RoleDefinition
from ansible_base.rbac.remote import RemoteObject


@pytest.mark.django_db
def test_give_remote_permission(rando):
    foo_type = DABContentType.objects.create(service='foo', model='foo')
    assert foo_type.service == 'foo'
    # TODO:
    # assert foo_type.model_class() is not None
    foo_foo = DABPermission.objects.create(codename='foo_foo', content_type=foo_type)
    # TODO: fix this in next commit
    # rd = RoleDefinition.objects.create_from_permissions(
    #     name='Foo fooers for the foos in foo service',
    #     permissions=['foo.foo_foo'],
    #     content_type=foo_type
    # )
    # a_foo = RemoteObject(content_type=foo_type, object_id=42)
    # rd.give_permission(rando, a_foo)
