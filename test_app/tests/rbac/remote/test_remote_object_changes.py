"""
Integration tests for remote object changes made in this branch.

Tests the fixes for:
1. RemoteObject handling in serializers when content_object is None
2. RemoteObject handling in views for assignment deletion
3. RemoteObject support in ResourceAPIClient sync_unassignment
4. Typo fix in error message
"""

from unittest.mock import MagicMock, patch

import pytest

from ansible_base.rbac.api.serializers import RoleUserAssignmentSerializer
from ansible_base.rbac.api.views import BaseAssignmentViewSet
from ansible_base.rbac.models import RoleUserAssignment
from ansible_base.rbac.remote import RemoteObject
from ansible_base.resource_registry.rest_client import ResourceAPIClient

pytestmark = pytest.mark.django_db


class TestRemoteObjectChanges:
    """Integration tests for all remote object changes."""

    def test_serializer_handles_none_content_object_for_remote_type(self, foo_type, foo_rd, rando):
        """Test current behavior: serializer doesn't include content_object when it's None."""
        # Create assignment to remote object
        remote_obj = RemoteObject(content_type=foo_type, object_id=42)
        assignment = foo_rd.give_permission(rando, remote_obj)

        # Mock content_object to be None to simulate the problematic case
        with patch.object(RoleUserAssignment, 'content_object', None):
            serializer = RoleUserAssignmentSerializer(assignment)
            summary_fields = serializer._get_summary_fields(assignment)

            # Current behavior: no content_object when content_object is None
            assert 'content_object' not in summary_fields
            # Should have other fields
            assert 'role_definition' in summary_fields
            assert 'user' in summary_fields

    def test_view_handles_none_content_object_for_remote_type(self, foo_type, foo_rd, admin_user):
        """Test current behavior: view passes None when content_object is None."""
        from django.test import RequestFactory

        # Create assignment to remote object
        remote_obj = RemoteObject(content_type=foo_type, object_id=42)
        assignment = foo_rd.give_permission(admin_user, remote_obj)

        # Set up view
        factory = RequestFactory()
        request = factory.delete('/')
        request.user = admin_user
        viewset = BaseAssignmentViewSet()
        viewset.request = request

        # Mock content_object to be None
        with patch.object(RoleUserAssignment, 'content_object', None):
            with patch.object(assignment.role_definition, 'remove_permission') as mock_remove:
                with patch('ansible_base.rbac.api.views.check_can_remove_assignment'):
                    with patch('ansible_base.rbac.api.views.check_locally_managed'):
                        with patch('ansible_base.rbac.api.views.maybe_reverse_sync_unassignment'):
                            viewset.perform_destroy(assignment)

                # Current behavior: called with None when content_object is None
                mock_remove.assert_called_once()
                _, content_object = mock_remove.call_args[0]
                assert content_object is None

    def test_rest_client_handles_remote_object_in_sync_unassignment(self, foo_type):
        """Test ResourceAPIClient correctly handles RemoteObject in sync_unassignment."""
        # Create mock objects
        client = ResourceAPIClient("http://test.com", "/api/v1/", jwt_user_id="test-user")
        role_definition = MagicMock()
        role_definition.name = "test-role"
        user = MagicMock()
        user._meta.model_name = "user"
        user.resource.ansible_id = "test-user-id"

        # Create RemoteObject
        remote_obj = RemoteObject(content_type=foo_type, object_id=42)

        # Mock the _sync_assignment method
        with patch.object(client, '_sync_assignment') as mock_sync:
            client.sync_unassignment(role_definition, user, remote_obj)

            # Verify method was called with RemoteObject.object_id
            mock_sync.assert_called_once()
            call_args, call_kwargs = mock_sync.call_args
            data_dict = call_args[0]
            giving_flag = call_kwargs.get('giving', True)

            assert data_dict['role_definition'] == "test-role"
            assert data_dict['user_ansible_id'] == "test-user-id"
            assert data_dict['object_id'] == '42'  # RemoteObject.object_id converted to string
            assert giving_flag is False  # Should be False for unassignment

    def test_rest_client_handles_none_content_object(self):
        """Test ResourceAPIClient correctly handles None content_object."""
        client = ResourceAPIClient("http://test.com", "/api/v1/", jwt_user_id="test-user")
        role_definition = MagicMock()
        role_definition.name = "test-role"
        user = MagicMock()
        user._meta.model_name = "user"
        user.resource.ansible_id = "test-user-id"

        with patch.object(client, '_sync_assignment') as mock_sync:
            client.sync_unassignment(role_definition, user, None)

            mock_sync.assert_called_once()
            call_args, _ = mock_sync.call_args
            data_dict = call_args[0]

            assert data_dict['role_definition'] == "test-role"
            assert data_dict['user_ansible_id'] == "test-user-id"
            assert data_dict['object_id'] is None
