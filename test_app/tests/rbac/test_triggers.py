from unittest.mock import MagicMock, patch

import pytest
from django.apps import apps
from django.test.utils import override_settings

from ansible_base.rbac.models import ObjectRole, RoleEvaluation, RoleTeamAssignment, RoleUserAssignment
from ansible_base.rbac.permission_registry import permission_registry
from ansible_base.rbac.triggers import bulk_rbac_caching, dab_post_migrate, post_migration_rbac_setup
from test_app.models import Inventory, Organization


@pytest.mark.django_db
def test_post_migrate_signals():
    mck = MagicMock()
    # corresponds to docs/apps/rbac/for_app_developers.md, Post-migrate Actions
    dab_post_migrate.connect(mck.ad_hoc_func, dispatch_uid="my_logic")
    post_migration_rbac_setup(apps.get_app_config('dab_rbac'))
    mck.ad_hoc_func.assert_called_once_with(sender=apps.get_app_config('dab_rbac'), signal=dab_post_migrate)


@pytest.mark.django_db
def test_change_parent_field(team, rando, inventory, org_inv_rd, member_rd):
    member_rd.give_permission(rando, team)
    org_inv_rd.give_permission(team, inventory.organization)
    assert rando.has_obj_perm(inventory, 'change')

    inventory.organization = Organization.objects.create(name='new-org')
    inventory.save()

    assert not rando.has_obj_perm(inventory, 'change')


@pytest.mark.django_db
def test_change_parent_field_with_only(team, rando, inventory, org_inv_rd, member_rd):
    member_rd.give_permission(rando, team)
    org_inv_rd.give_permission(team, inventory.organization)
    assert rando.has_obj_perm(inventory, 'change')

    inv_copy = Inventory.objects.only('id').get(id=inventory.id)
    assert 'organization_id' not in inv_copy.__dict__  # signal should not undermine .only

    inv_copy.organization = Organization.objects.create(name='new-org')
    inv_copy.save()

    assert not rando.has_obj_perm(inv_copy, 'change')


@pytest.mark.django_db
def test_perform_unrelated_update(inventory):
    """
    Signals should not trigger queries of permission related fields are not changed
    """
    inv_copy = Inventory.objects.only('id', 'name').get(id=inventory.id)
    assert 'organization_id' not in inv_copy.__dict__

    inv_copy.name = 'new inventory name'
    inv_copy.save()

    assert 'organization_id' not in inv_copy.__dict__


def gfk_filter(obj):
    "Test helper method, expects to be called before permissions are assigned"
    ct = permission_registry.content_type_model.objects.get_for_model(obj)
    gfk = {'object_id': obj.pk, 'content_type_id': ct.pk}
    # No roles are assigned in the starting state, this is a design objective
    assert not RoleEvaluation.objects.filter(**gfk).exists(), obj
    return gfk


@pytest.mark.django_db
@pytest.mark.parametrize('what_to_delete', ['user', 'org', 'object'])
def test_delete_signals_object(organization, inventory, rando, inv_rd, what_to_delete):
    user_id = rando.id
    inv_gfk = gfk_filter(inventory)
    org_gfk = gfk_filter(organization)

    assignment = inv_rd.give_permission(rando, inventory)

    assert RoleEvaluation.objects.filter(**org_gfk).count() == 0
    assert RoleEvaluation.objects.filter(**inv_gfk).count() == 2

    if what_to_delete == 'user':
        rando.delete()
    if what_to_delete == 'org':
        organization.delete()
    else:
        inventory.delete()

    assert not RoleEvaluation.objects.filter(**inv_gfk).exists()
    assert not RoleEvaluation.objects.filter(**org_gfk).exists()
    assert not RoleUserAssignment.objects.filter(user_id=user_id).exists()
    assert not ObjectRole.objects.filter(id=assignment.object_role_id).exists()


@pytest.mark.django_db
@pytest.mark.parametrize('what_to_delete', ['user', 'org', 'object'])
@pytest.mark.parametrize('cache_org', [True, False])
def test_delete_signals_organization(organization, inventory, rando, org_inv_change_rd, what_to_delete, cache_org):
    user_id = rando.id
    inv_gfk = gfk_filter(inventory)
    org_gfk = gfk_filter(organization)

    with override_settings(ANSIBLE_BASE_CACHE_PARENT_PERMISSIONS=cache_org):
        assignment = org_inv_change_rd.give_permission(rando, organization)
        assert RoleEvaluation.objects.filter(**org_gfk).count() == (4 if cache_org else 2)
        assert RoleEvaluation.objects.filter(**inv_gfk).count() == 2

        if what_to_delete == 'user':
            rando.delete()
        if what_to_delete == 'org':
            organization.delete()
        else:
            inventory.delete()

        assert not RoleEvaluation.objects.filter(**inv_gfk).exists()
        if what_to_delete == 'object':
            # The user and org still exist, so the membership should still exist
            assert RoleUserAssignment.objects.filter(user_id=user_id).count() == 1
            assert ObjectRole.objects.filter(id=assignment.object_role_id).count() == 1
            assert RoleEvaluation.objects.filter(**org_gfk).count() == (4 if cache_org else 2)
        else:
            assert not RoleUserAssignment.objects.filter(user_id=user_id).exists()
            assert not ObjectRole.objects.filter(id=assignment.object_role_id).exists()
            assert not RoleEvaluation.objects.filter(**org_gfk).exists()


@pytest.mark.django_db
@pytest.mark.parametrize('what_to_delete', ['team', 'org', 'object'])
def test_delete_signals_team_object(organization, inventory, team, inv_rd, what_to_delete):
    team_id = team.id
    inv_gfk = gfk_filter(inventory)
    org_gfk = gfk_filter(organization)
    assignment = inv_rd.give_permission(team, inventory)

    if what_to_delete == 'team':
        team.delete()
    if what_to_delete == 'org':
        organization.delete()
    else:
        inventory.delete()

    assert not RoleTeamAssignment.objects.filter(team_id=team_id).exists()
    assert not ObjectRole.objects.filter(id=assignment.object_role_id).exists()
    assert not RoleEvaluation.objects.filter(**inv_gfk).exists()
    assert not RoleEvaluation.objects.filter(**org_gfk).exists()


@pytest.mark.django_db
@pytest.mark.parametrize('what_to_delete', ['team', 'org', 'object'])
def test_delete_signals_team_organization(organization, inventory, team, org_inv_rd, what_to_delete):
    inv_gfk = gfk_filter(inventory)
    org_gfk = gfk_filter(organization)
    team_id = team.id
    assignment = org_inv_rd.give_permission(team, organization)

    if what_to_delete == 'team':
        team.delete()
    if what_to_delete == 'org':
        organization.delete()
    else:
        inventory.delete()

    if what_to_delete == 'object':
        assert RoleTeamAssignment.objects.filter(team_id=team_id).count() == 1  # team still has org role
        assert ObjectRole.objects.filter(id=assignment.object_role_id).count() == 1
        assert RoleEvaluation.objects.filter(**org_gfk).count() == 2
    else:
        assert not RoleTeamAssignment.objects.filter(team_id=team_id).exists()
        assert not ObjectRole.objects.filter(id=assignment.object_role_id).exists()
        assert not RoleEvaluation.objects.filter(**org_gfk).exists()

    assert not RoleEvaluation.objects.filter(**inv_gfk).exists()


@pytest.mark.django_db
class TestBulkRBACCaching:
    """Tests for the bulk_rbac_caching context manager"""

    def test_bulk_caching_defers_updates(self, rando, inv_rd, inventory):
        """Test that updates are deferred during bulk operations"""
        with (
            patch('ansible_base.rbac.triggers.compute_team_member_roles') as mock_team_update,
            patch('ansible_base.rbac.triggers.compute_object_role_permissions') as mock_obj_update,
        ):

            with bulk_rbac_caching():
                # Multiple permission assignments
                inv_rd.give_permission(rando, inventory)
                # During bulk mode, the expensive cache functions should not be called
                mock_team_update.assert_not_called()
                mock_obj_update.assert_not_called()

            # After exiting context, they should be called once
            mock_obj_update.assert_called_once()

    def test_bulk_caching_collects_object_roles(self, rando, team, inv_rd, org_inv_rd, inventory, organization):
        """Test that object roles are properly collected and updated in bulk"""
        with patch('ansible_base.rbac.triggers.compute_object_role_permissions') as mock_obj_update:

            with bulk_rbac_caching():
                # Multiple assignments that affect different object roles
                assignment1 = inv_rd.give_permission(rando, inventory)
                assignment2 = org_inv_rd.give_permission(team, organization)

                # Should not be called during bulk mode
                mock_obj_update.assert_not_called()

            # Should be called once with collected object roles
            mock_obj_update.assert_called_once()
            call_args = mock_obj_update.call_args
            object_roles = call_args.kwargs['object_roles']

            # Should contain both object roles
            assert assignment1.object_role in object_roles
            assert assignment2.object_role in object_roles

    def test_bulk_caching_handles_team_updates(self, rando, team, member_rd):
        """Test that team updates are properly deferred and executed"""
        with (
            patch('ansible_base.rbac.triggers.compute_team_member_roles') as mock_team_update,
            patch('ansible_base.rbac.triggers.compute_object_role_permissions') as mock_obj_update,
        ):

            with bulk_rbac_caching():
                # Assignment that affects team membership
                member_rd.give_permission(rando, team)

                # Should not be called during bulk mode
                mock_team_update.assert_not_called()
                mock_obj_update.assert_not_called()

            # Both should be called after exiting context
            mock_team_update.assert_called_once()
            mock_obj_update.assert_called_once()

    def test_bulk_caching_nested_contexts(self, rando, inv_rd, inventory):
        """Test that nested bulk contexts work correctly"""
        with patch('ansible_base.rbac.triggers.compute_object_role_permissions') as mock_obj_update:

            with bulk_rbac_caching():
                inv_rd.give_permission(rando, inventory)

                # Nested context
                with bulk_rbac_caching():
                    # Another assignment in nested context
                    # Should still not trigger updates
                    pass

                # Still in outer context, should not be called yet
                mock_obj_update.assert_not_called()

            # Only called once when exiting outermost context
            mock_obj_update.assert_called_once()

    def test_bulk_caching_with_multiple_assignments(self, rando, team, inv_rd, org_inv_rd, inventory, organization):
        """Test bulk caching works with multiple assignments that require updates"""
        with patch('ansible_base.rbac.triggers.compute_object_role_permissions') as mock_obj_update:

            with bulk_rbac_caching():
                # Multiple operations that create new object roles
                inv_rd.give_permission(rando, inventory)
                org_inv_rd.give_permission(team, organization)
                mock_obj_update.assert_not_called()

            # Should be called once after all operations
            mock_obj_update.assert_called_once()

    def test_bulk_caching_with_object_role_deletion(self, rando, inv_rd, inventory):
        """Test bulk caching when object role gets deleted during removal"""
        # First give permission normally
        inv_rd.give_permission(rando, inventory)

        with patch('ansible_base.rbac.triggers.compute_object_role_permissions') as mock_obj_update:

            with bulk_rbac_caching():
                # Remove permission in bulk mode - this will delete the object role
                inv_rd.remove_permission(rando, inventory)
                mock_obj_update.assert_not_called()

            # Should not be called since object role was deleted (nothing to update)
            mock_obj_update.assert_not_called()

    def test_bulk_caching_performance_benefit(self, rando, team, inv_rd, inventory):
        """Test that bulk operations actually reduce cache update calls"""
        with patch('ansible_base.rbac.triggers.compute_object_role_permissions') as mock_obj_update:

            # Without bulk caching - each assignment triggers an update
            inv_rd.give_permission(rando, inventory)
            inv_rd.remove_permission(rando, inventory)

            # Should have been called multiple times
            assert mock_obj_update.call_count >= 2

            mock_obj_update.reset_mock()

            # With bulk caching - should only be called once
            with bulk_rbac_caching():
                inv_rd.give_permission(rando, inventory)
                inv_rd.give_permission(team, inventory)
                inv_rd.remove_permission(rando, inventory)

            # Should only be called once
            mock_obj_update.assert_called_once()

    def test_bulk_caching_exception_handling(self, rando, inv_rd, inventory):
        """Test that bulk caching state is reset even if exception occurs"""
        with patch('ansible_base.rbac.triggers.compute_object_role_permissions') as mock_obj_update:

            try:
                with bulk_rbac_caching():
                    inv_rd.give_permission(rando, inventory)
                    raise ValueError("Test exception")
            except ValueError:
                pass

            # Should still be called even though exception occurred
            mock_obj_update.assert_called_once()

            mock_obj_update.reset_mock()

            # State should be reset, next operation should work normally
            inv_rd.give_permission(rando, inventory)
            mock_obj_update.assert_called()

    def test_no_bulk_caching_without_context(self, rando, inv_rd, inventory):
        """Test that normal operations still work when not in bulk context"""
        with patch('ansible_base.rbac.triggers.compute_object_role_permissions') as mock_obj_update:

            # Normal assignment should trigger immediate update
            inv_rd.give_permission(rando, inventory)
            mock_obj_update.assert_called()

    def test_bulk_caching_empty_context(self):
        """Test that empty bulk context doesn't call cache functions"""
        with (
            patch('ansible_base.rbac.triggers.compute_team_member_roles') as mock_team_update,
            patch('ansible_base.rbac.triggers.compute_object_role_permissions') as mock_obj_update,
        ):

            with bulk_rbac_caching():
                # No operations performed
                pass

            # Should not call expensive functions if no changes were made
            mock_team_update.assert_not_called()
            mock_obj_update.assert_not_called()
