import pytest
from django.contrib.auth import get_user_model

from ansible_base.rbac import permission_registry
from ansible_base.rbac.claims import get_user_claims
from ansible_base.rbac.models import RoleDefinition
from test_app.models import Inventory, Organization, Team


@pytest.mark.django_db
class TestUserClaims:
    def test_user_claims_comprehensive_permissions(self):
        """Test get_user_claims with a wide array of permissions including org admin, team membership, and global auditor role"""
        # Create a test user
        User = get_user_model()
        user = User.objects.create(username='test_claims_user', email='test@example.com')

        # Create test organization and team
        org = Organization.objects.create(name='Test Org')
        team = Team.objects.create(name='Test Team', organization=org)
        inventory = Inventory.objects.create(name='Test Inventory', organization=org)

        # Get or create role definitions we need

        # 1. Organization Admin role
        org_admin_rd = RoleDefinition.objects.create_from_permissions(
            permissions=['view_organization', 'change_organization', 'add_inventory', 'change_inventory', 'delete_inventory', 'view_inventory'],
            name='Organization Admin',
            content_type=permission_registry.content_type_model.objects.get_for_model(Organization),
            managed=True,
        )

        # 2. Team Member role
        team_member_rd = RoleDefinition.objects.create_from_permissions(
            permissions=[permission_registry.team_permission, f'view_{permission_registry.team_model._meta.model_name}'],
            name='Team Member',
            content_type=permission_registry.content_type_model.objects.get_for_model(Team),
            managed=True,
        )

        # 3. Platform Auditor role (global)
        platform_auditor_rd = RoleDefinition.objects.create_from_permissions(
            permissions=['view_organization', 'view_inventory', 'view_team'],
            name='Platform Auditor',
            content_type=None,  # Global role
            managed=True,
        )

        # 4. Direct inventory permission
        inventory_rd = RoleDefinition.objects.create_from_permissions(
            permissions=['change_inventory', 'view_inventory'],
            name='Inventory Editor',
            content_type=permission_registry.content_type_model.objects.get_for_model(Inventory),
            managed=True,
        )

        # Assign permissions to user
        # Make user an admin of the organization
        org_admin_rd.give_permission(user, org)

        # Make user a member of the team
        team_member_rd.give_permission(user, team)

        # Give user direct inventory permissions
        inventory_rd.give_permission(user, inventory)

        # Give user global Platform Auditor role
        platform_auditor_rd.give_global_permission(user)

        # Call the function under test
        claims = get_user_claims(user)

        # For now, assert that we get a dict structure
        # The user will fill in the expected structure later
        assert isinstance(claims, dict)

        # Placeholder assertion - user will replace this with actual expected structure
        expected_claims = {}
        assert claims == expected_claims
