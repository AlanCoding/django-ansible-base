import pytest

from ansible_base.lib.utils.response import get_relative_url
from test_app.models import Team, User


@pytest.mark.django_db
class TestRoleAssignmentAnsibleIdSerialization:
    """Test serialization of ansible_id fields in role assignment endpoints"""

    def test_role_user_assignment_serializes_user_ansible_id(self, admin_api_client, inventory, inv_rd):
        """Test that RoleUserAssignment API returns user_ansible_id instead of null"""
        user = User.objects.create(username='test-user')
        assignment = inv_rd.give_permission(user, inventory)

        # Verify user has a resource and ansible_id
        assert hasattr(user, 'resource')
        assert user.resource is not None
        assert user.resource.ansible_id is not None
        expected_ansible_id = str(user.resource.ansible_id)

        # Get the assignment via API
        url = get_relative_url('roleuserassignment-detail', kwargs={'pk': assignment.pk})
        response = admin_api_client.get(url)
        assert response.status_code == 200

        # The user_ansible_id field should be populated, not null
        assert response.data['user_ansible_id'] is not None
        assert response.data['user_ansible_id'] == expected_ansible_id

        # Also verify the user field contains the primary key for backward compatibility
        assert response.data['user'] == user.pk

    def test_role_team_assignment_serializes_team_ansible_id(self, admin_api_client, inventory, inv_rd, organization):
        """Test that RoleTeamAssignment API returns team_ansible_id instead of null"""
        team = Team.objects.create(name='test-team', organization=organization)
        assignment = inv_rd.give_permission(team, inventory)

        # Verify team has a resource and ansible_id
        assert hasattr(team, 'resource')
        assert team.resource is not None
        assert team.resource.ansible_id is not None
        expected_ansible_id = str(team.resource.ansible_id)

        # Get the assignment via API
        url = get_relative_url('roleteamassignment-detail', kwargs={'pk': assignment.pk})
        response = admin_api_client.get(url)
        assert response.status_code == 200

        # The team_ansible_id field should be populated, not null
        assert response.data['team_ansible_id'] is not None
        assert response.data['team_ansible_id'] == expected_ansible_id

        # Also verify the team field contains the primary key for backward compatibility
        assert response.data['team'] == team.pk

    def test_role_user_assignment_list_includes_ansible_id(self, admin_api_client, inventory, inv_rd):
        """Test that RoleUserAssignment list endpoint includes user_ansible_id"""
        user = User.objects.create(username='test-user-list')
        assignment = inv_rd.give_permission(user, inventory)
        expected_ansible_id = str(user.resource.ansible_id)

        # Get assignments list via API
        url = get_relative_url('roleuserassignment-list')
        response = admin_api_client.get(url)
        assert response.status_code == 200

        # Find our assignment in the results
        assignment_data = None
        for item in response.data['results']:
            if item['id'] == assignment.pk:
                assignment_data = item
                break

        assert assignment_data is not None
        assert assignment_data['user_ansible_id'] is not None
        assert assignment_data['user_ansible_id'] == expected_ansible_id

    def test_role_team_assignment_list_includes_ansible_id(self, admin_api_client, inventory, inv_rd, organization):
        """Test that RoleTeamAssignment list endpoint includes team_ansible_id"""
        team = Team.objects.create(name='test-team-list', organization=organization)
        assignment = inv_rd.give_permission(team, inventory)
        expected_ansible_id = str(team.resource.ansible_id)

        # Get assignments list via API
        url = get_relative_url('roleteamassignment-list')
        response = admin_api_client.get(url)
        assert response.status_code == 200

        # Find our assignment in the results
        assignment_data = None
        for item in response.data['results']:
            if item['id'] == assignment.pk:
                assignment_data = item
                break

        assert assignment_data is not None
        assert assignment_data['team_ansible_id'] is not None
        assert assignment_data['team_ansible_id'] == expected_ansible_id
