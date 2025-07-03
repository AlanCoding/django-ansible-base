import pytest

from ansible_base.rbac.models import RoleUserAssignment
from ansible_base.rbac.remote import RemoteObject
from test_app.models import User


@pytest.mark.django_db
def test_give_remote_permission(rando, foo_type, foo_permission, foo_rd):
    "Test for a few technical elements related to giving permission to remote objects, and using in query."
    assert foo_type.service == 'foo'  # a place, a domain, a server, known as foo
    assert foo_type.api_slug == 'foo.foo'  # there lives a foo in foo

    assert foo_permission.api_slug == 'foo.foo_foo'  # expression of the ability that one may foo a foo

    a_foo = RemoteObject(content_type=foo_type, object_id=42)
    assignment = foo_rd.give_permission(rando, a_foo)
    assert '42' in repr(a_foo)
    assert a_foo.pk == 42

    assignment = RoleUserAssignment.objects.get(pk=assignment.pk)
    assert assignment.content_object.pk == 42
    assert isinstance(assignment.content_object, RemoteObject)
    assert isinstance(assignment.content_object, RemoteObject)  # There was a bug where multiple references would error

    # We can do evaluation querysets, but these can not return objects, just id values
    assert set(foo_type.model_class().access_ids_qs(actor=rando, codename='foo')) == {(int(assignment.object_id),)}

    # Test that user-attached methods also work
    assert rando.has_obj_perm(a_foo, 'foo')
    with pytest.raises(RuntimeError) as exc:
        assert not rando.has_obj_perm(a_foo, 'bar')  # not a valid permission
    assert 'The permission bar_foo is not valid for model foo' in str(exc)


@pytest.mark.django_db
def test_prefetch_related_objects(foo_type, foo_rd, inv_rd, inventory):
    users = [User.objects.create(username=f'user{i}') for i in range(10)]

    a_foo = RemoteObject(content_type=foo_type, object_id=42)
    for u in users:
        foo_rd.give_permission(u, a_foo)
        inv_rd.give_permission(u, inventory)

    assert RoleUserAssignment.objects.count() == 20
    assert {assignment.content_object for assignment in RoleUserAssignment.objects.all()} == {a_foo, inventory}
    assert {assignment.content_object for assignment in RoleUserAssignment.objects.all()} == {a_foo, inventory}
    assert {assignment.content_object for assignment in RoleUserAssignment.objects.prefetch_related('content_object')} == {a_foo, inventory}
