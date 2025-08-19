from unittest.mock import patch

import pytest

from ansible_base.rbac.api.serializers import RoleUserAssignmentSerializer
from ansible_base.rbac.models import RoleUserAssignment
from ansible_base.rbac.remote import RemoteObject

pytestmark = pytest.mark.django_db


class TestRemoteObjectSerialization:
    """Test remote object handling in assignment serializers."""

    def test_summary_fields_with_prefetched_remote_object(self, foo_type, foo_rd, rando):
        """Test bug reproduction: prefetch_related causes remote objects to be cached as None.

        This reproduces the real Hub API DELETE bug where assignments to RemoteObjects
        fail because Django's prefetch_related incorrectly caches remote objects as None,
        causing the content_object property to return None even when the assignment
        has valid content_type_id and object_id.
        """
        # Create an assignment to a remote object (simulating Hub collection assignment)
        remote_obj = RemoteObject(content_type=foo_type, object_id=42)
        assignment = foo_rd.give_permission(rando, remote_obj)
        assignment.refresh_from_db()

        # Simulate the prefetch_related scenario that causes the bug
        # This happens when the API fetches assignments with prefetch_related('content_object')
        # but remote objects don't exist locally, so they get cached as None
        qs = RoleUserAssignment.objects.filter(id=assignment.id).prefetch_related('content_object')
        assignment_with_prefetch = qs.first()

        # Before the fix, prefetch_related would cache remote objects as None
        # The fix in FederatedForeignKey now detects this scenario and recreates the remote object
        assert assignment_with_prefetch.content_type_id is not None  # Valid assignment metadata
        assert assignment_with_prefetch.object_id is not None
        assert assignment_with_prefetch.content_type.service == 'foo'  # Remote service

        # VERIFY THE FIX: content_object should now be properly recreated even after prefetch_related
        # Previously this would be None, causing Hub DELETE operations to fail
        assert assignment_with_prefetch.content_object is not None  # Fix: FederatedForeignKey recreated it
        assert isinstance(assignment_with_prefetch.content_object, RemoteObject)
        assert assignment_with_prefetch.content_object.object_id == '42'
        assert assignment_with_prefetch.content_object.content_type == foo_type

        # The serializer should create proper summary fields for the remote object
        serializer = RoleUserAssignmentSerializer(assignment_with_prefetch)
        summary_fields = serializer._get_summary_fields(assignment_with_prefetch)

        # Should have content_object summary fields with remote object placeholder data
        assert 'content_object' in summary_fields
        content_obj_summary = summary_fields['content_object']
        assert content_obj_summary['<remote_object_placeholder>'] is True
        assert content_obj_summary['model_name'] == 'foo'
        assert content_obj_summary['service'] == 'foo'
        assert content_obj_summary['pk'] == 42

    def test_summary_fields_with_existing_content_object(self, foo_type, foo_rd, rando):
        """Test that summary_fields works normally when content_object exists."""
        remote_obj = RemoteObject(content_type=foo_type, object_id=42)
        assignment = foo_rd.give_permission(rando, remote_obj)

        serializer = RoleUserAssignmentSerializer(assignment)
        summary_fields = serializer._get_summary_fields(assignment)

        # Should have content_object summary fields from the actual object
        assert 'content_object' in summary_fields
        content_obj_summary = summary_fields['content_object']
        assert content_obj_summary['<remote_object_placeholder>'] is True
        assert content_obj_summary['pk'] == 42

    def test_summary_fields_with_non_remote_object(self, inventory, inv_rd, rando):
        """Test that summary_fields doesn't create RemoteObject for non-remote models."""
        assignment = inv_rd.give_permission(rando, inventory)

        # Mock content_object to be None for a non-remote model
        with patch.object(RoleUserAssignment, 'content_object', None):
            serializer = RoleUserAssignmentSerializer(assignment)
            summary_fields = serializer._get_summary_fields(assignment)

            # Should not have content_object summary fields since content_object is None
            # and the model is not a RemoteObject
            assert 'content_object' not in summary_fields

    def test_summary_fields_with_object_without_summary_fields_method(self, foo_type, foo_rd, rando):
        """Test that summary_fields handles objects without summary_fields method gracefully."""
        remote_obj = RemoteObject(content_type=foo_type, object_id=42)
        assignment = foo_rd.give_permission(rando, remote_obj)

        # Mock the content_object to be an object without summary_fields method
        mock_obj = object()

        with patch.object(RoleUserAssignment, 'content_object', mock_obj):
            serializer = RoleUserAssignmentSerializer(assignment)
            summary_fields = serializer._get_summary_fields(assignment)

            # Should not have content_object summary fields since object has no summary_fields method
            assert 'content_object' not in summary_fields
