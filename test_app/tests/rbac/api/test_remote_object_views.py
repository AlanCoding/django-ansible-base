from unittest.mock import patch

import pytest
from django.test import RequestFactory

from ansible_base.rbac.api.views import BaseAssignmentViewSet
from ansible_base.rbac.models import RoleUserAssignment
from ansible_base.rbac.remote import RemoteObject

pytestmark = pytest.mark.django_db


class TestRemoteObjectViews:
    """Test remote object handling in assignment views."""

    def test_perform_destroy_with_prefetched_remote_object_bug_reproduction(self, foo_type, foo_rd, rando):
        """Test the actual Hub DELETE bug: prefetch_related causes remote object content_object to be None.

        This reproduces the real Hub API DELETE failure where assignments to Hub RemoteObjects
        fail because Django's prefetch_related caches remote objects as None, but the view
        still needs to process the DELETE operation correctly.
        """
        # Create an assignment to a remote object (like a Hub collection)
        remote_obj = RemoteObject(content_type=foo_type, object_id=42)
        assignment = foo_rd.give_permission(rando, remote_obj)
        assignment.refresh_from_db()

        # Simulate the API scenario that causes the bug:
        # GET /api/v1/role_user_assignments/ uses prefetch_related('content_object')
        # which caches remote objects as None since they don't exist locally
        qs = RoleUserAssignment.objects.filter(id=assignment.id).prefetch_related('content_object')
        assignment_with_prefetch = qs.first()

        # Verify assignment metadata is valid (the Hub assignment scenario)
        assert assignment_with_prefetch.content_type_id is not None  # Has valid metadata
        assert assignment_with_prefetch.object_id is not None
        assert assignment_with_prefetch.content_type.service == 'foo'  # Remote service

        # VERIFY THE FIX: Before the fix, content_object would be None due to prefetch caching
        # The FederatedForeignKey fix now properly recreates the remote object
        assert assignment_with_prefetch.content_object is not None  # Fix: object recreated
        assert isinstance(assignment_with_prefetch.content_object, RemoteObject)

        # Create view for DELETE operation (the failing Hub API operation)
        factory = RequestFactory()
        request = factory.delete('/')
        request.user = rando
        viewset = BaseAssignmentViewSet()
        viewset.request = request

        # Mock the remove_permission method to verify DELETE operation works
        with patch.object(assignment_with_prefetch.role_definition, 'remove_permission') as mock_remove:
            # Mock other required methods for clean test
            with patch('ansible_base.rbac.api.views.check_can_remove_assignment'):
                with patch('ansible_base.rbac.api.views.check_locally_managed'):
                    with patch('ansible_base.rbac.api.views.maybe_reverse_sync_unassignment'):
                        # This should now work - the Hub DELETE bug is fixed
                        viewset.perform_destroy(assignment_with_prefetch)

            # Verify the DELETE operation worked correctly
            mock_remove.assert_called_once()
            args, _ = mock_remove.call_args
            actor, content_object = args

            assert actor == rando
            # With the FederatedForeignKey fix, content_object is properly passed
            assert isinstance(content_object, RemoteObject)
            assert content_object.object_id == '42'
            assert content_object.content_type == foo_type

    def test_perform_destroy_with_existing_content_object(self, foo_type, foo_rd, rando):
        """Test that perform_destroy works normally when content_object exists."""
        remote_obj = RemoteObject(content_type=foo_type, object_id=42)
        assignment = foo_rd.give_permission(rando, remote_obj)

        factory = RequestFactory()
        request = factory.delete('/')
        request.user = rando

        viewset = BaseAssignmentViewSet()
        viewset.request = request

        # Mock the remove_permission method to track what gets called
        with patch.object(assignment.role_definition, 'remove_permission') as mock_remove:
            # Mock other required methods
            with patch('ansible_base.rbac.api.views.check_can_remove_assignment'):
                with patch('ansible_base.rbac.api.views.check_locally_managed'):
                    with patch('ansible_base.rbac.api.views.maybe_reverse_sync_unassignment'):
                        viewset.perform_destroy(assignment)

            # Verify remove_permission was called with the original remote object
            mock_remove.assert_called_once()
            args, _ = mock_remove.call_args
            actor, content_object = args

            assert actor == rando
            assert isinstance(content_object, RemoteObject)
            assert content_object.object_id == 42  # Integer when not from prefetch scenario

    def test_perform_destroy_with_non_remote_object(self, inventory, inv_rd, rando):
        """Test that perform_destroy doesn't create RemoteObject for non-remote models."""
        assignment = inv_rd.give_permission(rando, inventory)

        factory = RequestFactory()
        request = factory.delete('/')
        request.user = rando

        viewset = BaseAssignmentViewSet()
        viewset.request = request

        # Mock content_object to be None for a non-remote model
        with patch.object(RoleUserAssignment, 'content_object', None):
            with patch.object(assignment.role_definition, 'remove_permission') as mock_remove:
                with patch('ansible_base.rbac.api.views.check_can_remove_assignment'):
                    with patch('ansible_base.rbac.api.views.check_locally_managed'):
                        with patch('ansible_base.rbac.api.views.maybe_reverse_sync_unassignment'):
                            viewset.perform_destroy(assignment)

                # Verify remove_permission was called with None since content_object is None
                # and the model is not a RemoteObject
                mock_remove.assert_called_once()
                args, _ = mock_remove.call_args
                actor, content_object = args

                assert actor == rando
                assert content_object is None

    def test_perform_destroy_global_assignment(self, global_inv_rd, rando):
        """Test that perform_destroy handles global assignments correctly."""
        assignment = global_inv_rd.give_global_permission(rando)

        # Ensure assignment has no content_type_id for global assignment
        assignment.content_type_id = None
        assignment.object_id = None

        factory = RequestFactory()
        request = factory.delete('/')
        request.user = rando

        viewset = BaseAssignmentViewSet()
        viewset.request = request

        # Mock the remove_global_permission method
        with patch.object(assignment.role_definition, 'remove_global_permission') as mock_remove_global:
            with patch('ansible_base.rbac.api.views.check_can_remove_assignment'):
                with patch('ansible_base.rbac.api.views.check_locally_managed'):
                    with patch('ansible_base.rbac.api.views.maybe_reverse_sync_unassignment'):
                        viewset.perform_destroy(assignment)

            # Verify remove_global_permission was called for global assignment
            mock_remove_global.assert_called_once_with(rando)
