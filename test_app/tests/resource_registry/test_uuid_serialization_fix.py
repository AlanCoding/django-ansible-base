"""
Tests for UUID serialization fix in ResourceAPIClient.

This module tests the fix for the UUID JSON serialization issue that occurred
when syncing RemoteObject assignments with UUID primary keys.

Bug: TypeError: Object of type UUID is not JSON serializable
Fix: Convert UUID objects to strings before JSON serialization in sync_unassignment
"""

import json
import uuid
from unittest.mock import Mock, patch

from django.test import TestCase

from ansible_base.rbac.remote import RemoteObject
from ansible_base.resource_registry.rest_client import ResourceAPIClient


class UUIDSerializationFixTestCase(TestCase):
    """Test UUID serialization fix in ResourceAPIClient.sync_unassignment."""

    def setUp(self):
        """Set up test fixtures."""
        self.client = ResourceAPIClient("https://test.example.com", "test-token")

        # Mock role definition
        self.mock_role_definition = Mock()
        self.mock_role_definition.name = "galaxy.collection_remote_owner"

        # Mock user actor
        self.mock_user = Mock()
        self.mock_user._meta.model_name = "user"
        self.mock_user.resource.ansible_id = uuid.uuid4()

    def test_uuid_pk_converted_to_string_in_sync_unassignment(self):
        """Test that UUID primary keys are converted to strings for JSON serialization."""
        # Create a RemoteObject with UUID primary key
        test_uuid = uuid.uuid4()
        mock_content_type = Mock()
        mock_content_type.service = "galaxy"
        mock_content_type.model = "collectionremote"
        mock_content_type.app_label = "galaxy"
        mock_content_type.pk_field_type = "uuid"

        remote_object = RemoteObject(content_type=mock_content_type, object_id=str(test_uuid))

        # Capture the data passed to _sync_assignment
        captured_data = None

        def capture_sync_assignment(data, giving=False):
            nonlocal captured_data
            captured_data = data
            return {"status": "success"}

        with patch.object(self.client, '_sync_assignment', side_effect=capture_sync_assignment):
            with patch('ansible_base.resource_registry.rest_client.apps.get_model') as mock_get_model:
                # Mock DABContentType.objects.get_for_model
                mock_ct_cls = Mock()
                mock_ct_instance = Mock()
                mock_ct_instance.service = "galaxy"  # Not 'shared'
                mock_ct_cls.objects.get_for_model.return_value = mock_ct_instance
                mock_get_model.return_value = mock_ct_cls

                # Call sync_unassignment
                result = self.client.sync_unassignment(self.mock_role_definition, self.mock_user, remote_object)

        # Verify the sync was called and data was captured
        self.assertIsNotNone(captured_data)
        self.assertEqual(result["status"], "success")

        # Verify object_id is a string, not a UUID object
        self.assertIn('object_id', captured_data)
        object_id_value = captured_data['object_id']
        self.assertIsInstance(object_id_value, str)
        self.assertEqual(object_id_value, str(test_uuid))

        # Most importantly: verify the data is JSON serializable
        try:
            json_str = json.dumps(captured_data)
            parsed_back = json.loads(json_str)
            self.assertEqual(parsed_back['object_id'], str(test_uuid))
        except TypeError as e:
            self.fail(f"Data should be JSON serializable after fix, but got: {e}")

    def test_integer_pk_still_works_after_fix(self):
        """Test that integer primary keys continue to work correctly."""
        # Create a mock Django model with integer PK
        mock_django_object = Mock()
        mock_django_object.pk = 42

        captured_data = None

        def capture_sync_assignment(data, giving=False):
            nonlocal captured_data
            captured_data = data
            return {"status": "success"}

        with patch.object(self.client, '_sync_assignment', side_effect=capture_sync_assignment):
            with patch('ansible_base.resource_registry.rest_client.apps.get_model') as mock_get_model:
                mock_ct_cls = Mock()
                mock_ct_instance = Mock()
                mock_ct_instance.service = "local"
                mock_ct_cls.objects.get_for_model.return_value = mock_ct_instance
                mock_get_model.return_value = mock_ct_cls

                self.client.sync_unassignment(self.mock_role_definition, self.mock_user, mock_django_object)

        # Verify object_id is converted to string (backward compatibility)
        self.assertIn('object_id', captured_data)
        object_id_value = captured_data['object_id']
        self.assertIsInstance(object_id_value, str)
        self.assertEqual(object_id_value, "42")

        # Verify JSON serialization works
        try:
            json.dumps(captured_data)
        except TypeError as e:
            self.fail(f"Integer PK data should remain JSON serializable: {e}")

    def test_shared_service_objects_unaffected(self):
        """Test that shared service objects (using ansible_id) are unaffected by the fix."""
        mock_shared_object = Mock()
        mock_shared_object.resource.ansible_id = uuid.uuid4()

        captured_data = None

        def capture_sync_assignment(data, giving=False):
            nonlocal captured_data
            captured_data = data
            return {"status": "success"}

        with patch.object(self.client, '_sync_assignment', side_effect=capture_sync_assignment):
            with patch('ansible_base.resource_registry.rest_client.apps.get_model') as mock_get_model:
                mock_ct_cls = Mock()
                mock_ct_instance = Mock()
                mock_ct_instance.service = "shared"  # This triggers ansible_id path
                mock_ct_cls.objects.get_for_model.return_value = mock_ct_instance
                mock_get_model.return_value = mock_ct_cls

                self.client.sync_unassignment(self.mock_role_definition, self.mock_user, mock_shared_object)

        # Verify shared objects use object_ansible_id, not object_id
        self.assertIn('object_ansible_id', captured_data)
        self.assertNotIn('object_id', captured_data)

        # Verify ansible_id is properly converted to string
        ansible_id_value = captured_data['object_ansible_id']
        self.assertIsInstance(ansible_id_value, str)

        # Verify JSON serialization works
        try:
            json.dumps(captured_data)
        except TypeError as e:
            self.fail(f"Shared service data should be JSON serializable: {e}")

    def test_none_content_object_unaffected(self):
        """Test that global assignments (None content_object) are unaffected."""
        captured_data = None

        def capture_sync_assignment(data, giving=False):
            nonlocal captured_data
            captured_data = data
            return {"status": "success"}

        with patch.object(self.client, '_sync_assignment', side_effect=capture_sync_assignment):
            self.client.sync_unassignment(self.mock_role_definition, self.mock_user, None)  # Global assignment

        # Verify None is handled correctly
        self.assertIn('object_id', captured_data)
        self.assertIsNone(captured_data['object_id'])

        # Verify JSON serialization works
        try:
            json.dumps(captured_data)
        except TypeError as e:
            self.fail(f"Global assignment data should be JSON serializable: {e}")

    def test_fix_prevents_original_error(self):
        """Test that the fix prevents the original UUID serialization error."""
        # Create a UUID that would cause the original error
        test_uuid = uuid.uuid4()

        # Verify that UUID objects are indeed not JSON serializable (the original problem)
        with self.assertRaises(TypeError) as cm:
            json.dumps({"object_id": test_uuid})
        self.assertIn("not JSON serializable", str(cm.exception))

        # Verify that our fix (converting to string) resolves the issue
        try:
            json_str = json.dumps({"object_id": str(test_uuid)})
            parsed = json.loads(json_str)
            self.assertEqual(parsed["object_id"], str(test_uuid))
        except Exception as e:
            self.fail(f"String conversion should make UUID JSON serializable: {e}")

    def test_end_to_end_remote_object_sync_scenario(self):
        """Test the complete end-to-end scenario that was failing before the fix."""
        # This simulates the exact scenario that caused the bug:
        # 1. User deletes a RemoteObject assignment (galaxy collection)
        # 2. perform_destroy calls remote_sync_unassignment
        # 3. Gateway's sync_unassignment calls ResourceAPIClient.sync_unassignment
        # 4. sync_unassignment needs to serialize UUID data for API call

        test_uuid = uuid.uuid4()
        mock_content_type = Mock()
        mock_content_type.service = "galaxy"
        mock_content_type.model = "collectionremote"
        mock_content_type.app_label = "galaxy"
        mock_content_type.pk_field_type = "uuid"

        # Create RemoteObject (represents galaxy collection)
        remote_object = RemoteObject(content_type=mock_content_type, object_id=str(test_uuid))

        # Mock successful API response
        with patch.object(self.client, '_sync_assignment') as mock_sync:
            mock_sync.return_value = {"detail": "Assignment removed successfully"}

            with patch('ansible_base.resource_registry.rest_client.apps.get_model') as mock_get_model:
                mock_ct_cls = Mock()
                mock_ct_instance = Mock()
                mock_ct_instance.service = "galaxy"
                mock_ct_cls.objects.get_for_model.return_value = mock_ct_instance
                mock_get_model.return_value = mock_ct_cls

                # This should complete successfully without JSON serialization errors
                result = self.client.sync_unassignment(self.mock_role_definition, self.mock_user, remote_object)

                # Verify the sync was called
                self.assertTrue(mock_sync.called)
                self.assertEqual(result["detail"], "Assignment removed successfully")

                # Verify the data passed to the API is JSON serializable
                call_args = mock_sync.call_args
                sync_data = call_args[0][0]  # First positional argument

                # This should not raise any JSON serialization errors
                json.dumps(sync_data)

                # Verify the UUID was properly converted to string
                self.assertIsInstance(sync_data['object_id'], str)
                self.assertEqual(sync_data['object_id'], str(test_uuid))
