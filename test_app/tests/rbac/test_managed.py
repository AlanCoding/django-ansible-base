import pytest
from django.apps import apps

from ansible_base.rbac import permission_registry
from ansible_base.rbac.managed import OrganizationMember, managed_role_templates
from ansible_base.rbac.models import DABPermission, RoleDefinition, RoleEvaluation
from ansible_base.rbac.validators import validate_permissions_for_model


@pytest.mark.django_db
def test_courtesy_roles_pass_validation():
    """Because these use migration apps, we can not use normal model code, so we validate in tests"""
    for template_name, cls in managed_role_templates.items():
        if '_base' in template_name:
            continue  # abstract, not intended to be used
        constructor = cls()
        perm_list = []
        for str_perm in constructor.get_permissions(apps):
            if '.' in str_perm:
                perm_list.append(DABPermission.objects.get(api_slug=str_perm))
            else:
                perm_list.append(DABPermission.objects.get(codename=str_perm))
        model_cls = constructor.get_model(apps)
        if model_cls is not None:
            ct = permission_registry.content_type_model.objects.get_for_model(constructor.get_model(apps))
        else:
            ct = None  # system role
        validate_permissions_for_model(perm_list, ct, managed=True)


@pytest.mark.django_db
def test_cow_admin():
    rd = RoleDefinition.objects.managed.cow_admin
    perm_list = [perm.codename for perm in rd.permissions.all()]
    assert set(perm_list) == {'change_cow', 'view_cow', 'delete_cow', 'say_cow'}


@pytest.mark.django_db
def test_cow_mooer():
    rd = RoleDefinition.objects.managed.cow_moo
    perm_list = [perm.codename for perm in rd.permissions.all()]
    assert set(perm_list) == {'view_cow', 'say_cow'}
    assert rd.name == 'Cow Mooer'


@pytest.mark.django_db
def test_create_all_managed_roles():
    "This is a method that may be called in migrations, etc."
    assert not RoleDefinition.objects.filter(name='Cow Mooer').exists()
    permission_registry.create_managed_roles(apps)


@pytest.mark.django_db
def test_org_member_can_see_teams_in_org(rando, organization, team, org_member_rd):
    """Organization members should be able to view teams within that organization"""
    Team = permission_registry.team_model
    assert set(RoleEvaluation.accessible_objects(Team, rando, 'view_team')) == set()

    org_member_rd.give_permission(rando, organization)

    assert set(RoleEvaluation.accessible_objects(Team, rando, 'view_team')) == {team}


@pytest.mark.django_db
def test_org_member_cannot_see_teams_in_other_org(rando, organization, team, org_member_rd):
    """Organization members should not see teams from other organizations"""
    from test_app.models import Organization as OrgModel

    Team = permission_registry.team_model
    other_org = OrgModel.objects.create(name='other-org')
    other_team = Team.objects.create(name='other-team', organization=other_org)

    org_member_rd.give_permission(rando, organization)

    visible = set(RoleEvaluation.accessible_objects(Team, rando, 'view_team'))
    assert other_team not in visible


@pytest.mark.django_db
def test_create_managed_roles_update_perms_refreshes_existing_role():
    """When create_managed_roles is called with update_perms=True,
    it should update permissions on roles that already exist."""
    org_member_rd = RoleDefinition.objects.managed.org_member
    original_perms = set(org_member_rd.permissions.values_list('codename', flat=True))

    # Add a spurious permission to simulate drift
    extra_perm = DABPermission.objects.get(codename='view_organization')
    view_team_perm = DABPermission.objects.get(codename='view_team')
    org_member_rd.permissions.add(view_team_perm)
    assert 'view_team' in set(org_member_rd.permissions.values_list('codename', flat=True))

    # Without update_perms, the existing role is not touched
    permission_registry.create_managed_roles(apps, update_perms=False)
    org_member_rd.refresh_from_db()
    assert 'view_team' in set(org_member_rd.permissions.values_list('codename', flat=True))

    # With update_perms=True, permissions are reset to the managed definition
    permission_registry.create_managed_roles(apps, update_perms=True)
    org_member_rd.refresh_from_db()
    assert set(org_member_rd.permissions.values_list('codename', flat=True)) == original_perms

    RoleDefinition.objects.managed.clear()


@pytest.mark.django_db
def test_create_managed_roles_update_perms_adds_new_permission():
    """When a managed role constructor's permissions change and
    create_managed_roles is called with update_perms=True, the new
    permission should be added to the existing role definition."""
    org_member_rd = RoleDefinition.objects.managed.org_member
    original_perms = set(org_member_rd.permissions.values_list('codename', flat=True))
    assert 'change_organization' not in original_perms

    # Swap in a constructor that returns an expanded permission set
    class OrgMemberWithChange(OrganizationMember):
        def get_permissions(self, apps) -> set[str]:
            return super().get_permissions(apps) | {'change_organization'}

    old_constructor = permission_registry._managed_roles.get('org_member')
    permission_registry._managed_roles['org_member'] = OrgMemberWithChange()

    try:
        permission_registry.create_managed_roles(apps, update_perms=True)
        org_member_rd.refresh_from_db()
        new_perms = set(org_member_rd.permissions.values_list('codename', flat=True))
        assert 'change_organization' in new_perms
    finally:
        if old_constructor:
            permission_registry._managed_roles['org_member'] = old_constructor
        RoleDefinition.objects.managed.clear()
