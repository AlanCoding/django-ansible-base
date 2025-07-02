import pytest

from ansible_base.rbac.models import DABContentType, DABPermission, RoleDefinition
from ansible_base.rbac.remote import RemoteObject


@pytest.mark.django_db
def test_give_remote_permission(rando):
    foo_type = DABContentType.objects.create(service='foo', model='foo', app_label='foo')
    assert foo_type.service == 'foo'
    DABPermission.objects.create(codename='foo_foo', content_type=foo_type)
    rd = RoleDefinition.objects.create_from_permissions(name='Foo fooers for the foos in foo service', permissions=['foo.foo_foo'], content_type=foo_type)
    a_foo = RemoteObject(content_type=foo_type, object_id=42)
    rd.give_permission(rando, a_foo)
