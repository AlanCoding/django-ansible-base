import pytest

from ansible_base.lib.utils.response import get_relative_url
from test_app.models import Team


@pytest.mark.django_db
class TestTeamAssignmentPrimaryKey:
    """Test that team assignments work correctly when using team primary key instead of ansible_id"""

    def test_create_team_assignment_with_primary_key(self, admin_api_client, inventory, inv_rd, organization):
        """Test creating a team assignment using team primary key (reproduces bug report)"""
        # Create a team
        team = Team.objects.create(name='test-team', organization=organization)

        # Prepare request data matching the bug report
        url = get_relative_url('roleteamassignment-list')
        data = {'team': team.id, 'role_definition': inv_rd.id, 'object_id': inventory.id}  # Using primary key, not ansible_id

        # This should succeed with 201, not fail with 400
        response = admin_api_client.post(url, data=data, format="json")
        assert response.status_code == 201, f"Expected 201, got {response.status_code}. Response data: {response.data}"

        # Verify the assignment was created correctly
        assert response.data['team'] == team.id
        assert response.data['role_definition'] == inv_rd.id
        assert response.data['object_id'] == str(inventory.id)

        # Verify that team_ansible_id is also populated in the response
        assert response.data['team_ansible_id'] is not None
        assert response.data['team_ansible_id'] == str(team.resource.ansible_id)

    def test_create_team_assignment_with_ansible_id_still_works(self, admin_api_client, inventory, inv_rd, organization):
        """Test that the ansible_id approach still works (regression test)"""
        # Create a team
        team = Team.objects.create(name='test-team-ansible-id', organization=organization)

        # Prepare request data using ansible_id
        url = get_relative_url('roleteamassignment-list')
        data = {'team_ansible_id': str(team.resource.ansible_id), 'role_definition': inv_rd.id, 'object_id': inventory.id}  # Using ansible_id

        # This should also succeed with 201
        response = admin_api_client.post(url, data=data, format="json")
        assert response.status_code == 201, f"Expected 201, got {response.status_code}. Response data: {response.data}"

        # Verify the assignment was created correctly
        assert response.data['team'] == team.id
        assert response.data['role_definition'] == inv_rd.id
        assert response.data['object_id'] == str(inventory.id)
        assert response.data['team_ansible_id'] == str(team.resource.ansible_id)

    def test_providing_both_team_and_team_ansible_id_fails(self, admin_api_client, inventory, inv_rd, organization):
        """Test that providing both team and team_ansible_id results in validation error"""
        # Create a team
        team = Team.objects.create(name='test-team-both', organization=organization)

        # Prepare request data with both fields
        url = get_relative_url('roleteamassignment-list')
        data = {'team': team.id, 'team_ansible_id': str(team.resource.ansible_id), 'role_definition': inv_rd.id, 'object_id': inventory.id}

        # This should fail with 400
        response = admin_api_client.post(url, data=data, format="json")
        assert response.status_code == 400, f"Expected 400, got {response.status_code}. Response data: {response.data}"

        # Both fields should have the validation error
        assert 'Provide exactly one of team or team_ansible_id' in str(response.data['team'])
        assert 'Provide exactly one of team or team_ansible_id' in str(response.data['team_ansible_id'])

    def test_providing_neither_team_nor_team_ansible_id_fails(self, admin_api_client, inventory, inv_rd):
        """Test that providing neither team nor team_ansible_id results in validation error"""
        # Prepare request data with neither field
        url = get_relative_url('roleteamassignment-list')
        data = {'role_definition': inv_rd.id, 'object_id': inventory.id}

        # This should fail with 400
        response = admin_api_client.post(url, data=data, format="json")
        assert response.status_code == 400, f"Expected 400, got {response.status_code}. Response data: {response.data}"

        # Both fields should have the validation error
        assert 'Provide exactly one of team or team_ansible_id' in str(response.data['team'])
        assert 'Provide exactly one of team or team_ansible_id' in str(response.data['team_ansible_id'])
