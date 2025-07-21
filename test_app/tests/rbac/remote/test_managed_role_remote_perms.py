import pytest
from django.apps import apps
from django.test import override_settings

from ansible_base.rbac import permission_registry
from ansible_base.rbac.models import DABContentType, DABPermission, RoleDefinition
from ansible_base.rbac.remote import get_resource_prefix


@pytest.mark.django_db
@override_settings(ANSIBLE_BASE_MANAGED_ROLE_REGISTRY={'org_admin': {}})
def test_remote_permissions_on_create(foo_permission):
    rd = RoleDefinition.objects.managed.org_admin
    assert foo_permission in rd.permissions.all()


@pytest.mark.django_db
def test_remote_permission_refresh(foo_type):
    rd = RoleDefinition.objects.managed.org_admin

    foo_permission = DABPermission.objects.create(codename='foo_foo', content_type=foo_type)

    # the foo_permission was created after the managed role
    # so the role is not explicitly created
    assert foo_permission not in rd.permissions.all()

    # Loading it requires the refresh call
    permission_registry.create_managed_roles(apps, update_perms=True)
    assert foo_permission in rd.permissions.all()


@pytest.mark.django_db
def test_remote_permission_load_update_roles():
    rd = RoleDefinition.objects.managed.org_admin
    DABContentType.objects.load_remote_objects(
        [
            {'service': 'fooland', 'app_label': 'foo', 'model': 'foo', 'api_slug': 'fooland.foo', 'parent_content_type': 'shared.organization'},
            {'service': 'fooland', 'app_label': 'foo', 'model': 'bar', 'api_slug': 'fooland.bar', 'parent_content_type': None},
        ]
    )
    assert not DABPermission.objects.filter(codename='foo_foo').exists()
    DABPermission.objects.load_remote_objects(
        [
            {'codename': 'foo_foo', 'content_type': 'fooland.foo', 'api_slug': "fooland.foo_foo"},
            {'codename': 'bar_bar', 'content_type': 'fooland.bar', 'api_slug': "fooland.bar_bar"},
        ],
        update_managed=True,
    )
    assert DABPermission.objects.filter(codename='foo_foo').exists()

    foo_permission = DABPermission.objects.get(codename='foo_foo')
    bar_permission = DABPermission.objects.get(codename='bar_bar')
    assert foo_permission in rd.permissions.all()
    assert bar_permission not in rd.permissions.all()  # not child type of organization


@pytest.mark.django_db
def test_remote_permission_duplicate_name():
    rd = RoleDefinition.objects.managed.org_admin
    DABContentType.objects.load_remote_objects(
        [
            {'service': 'foo', 'app_label': 'core', 'model': 'thing', 'api_slug': 'foo.thing', 'parent_content_type': 'shared.organization'},
            {'service': 'bar', 'app_label': 'core', 'model': 'thing', 'api_slug': 'bar.thing', 'parent_content_type': 'shared.organization'},
        ]
    )
    ct = DABContentType.objects.get(api_slug='foo.thing')
    assert get_resource_prefix(ct.model_class()) == 'foo'

    assert not DABPermission.objects.filter(codename='view_thing').exists()
    DABPermission.objects.load_remote_objects(
        [
            {'codename': 'view_thing', 'content_type': 'foo.thing', 'api_slug': "foo.view_thing"},
            {'codename': 'view_thing', 'content_type': 'bar.thing', 'api_slug': "bar.view_thing"},
        ],
        update_managed=True,
    )
    assert DABPermission.objects.filter(codename='view_thing').count() == 2

    foo_permission = DABPermission.objects.get(api_slug='foo.view_thing')
    bar_permission = DABPermission.objects.get(api_slug='bar.view_thing')
    # Both are valid permissions for the org_admin role
    assert foo_permission in rd.permissions.all()
    assert bar_permission in rd.permissions.all()
