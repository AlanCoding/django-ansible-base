"""
Tests for FederatedForeignKey functionality and helper methods.

This module tests the refactored FederatedForeignKey methods to ensure
80%+ coverage on the new helper methods introduced for complexity reduction.
"""

from unittest.mock import Mock, patch

import pytest
from django.core.exceptions import ObjectDoesNotExist

from ansible_base.rbac.models import RoleUserAssignment
from ansible_base.rbac.models.fields import FederatedForeignKey
from ansible_base.rbac.remote import RemoteObject

pytestmark = pytest.mark.django_db


class TestFederatedForeignKeyHelperMethods:
    """Test the helper methods added during the cognitive complexity refactor."""

    def setup_method(self):
        """Set up test fixtures."""
        self.field = FederatedForeignKey(ct_field="content_type", fk_field="object_id")
        self.mock_instance = Mock()
        self.mock_instance._meta.get_field.return_value.attname = "content_type_id"

    def test_get_field_values_extracts_correct_values(self):
        """Test _get_field_values correctly extracts content type ID and object ID."""
        # Setup mock instance
        self.mock_instance.content_type_id = 123
        self.mock_instance.object_id = 456

        # Call the method
        ct_id, pk_val = self.field._get_field_values(self.mock_instance)

        # Verify results
        assert ct_id == 123
        assert pk_val == 456
        self.mock_instance._meta.get_field.assert_called_once_with("content_type")

    def test_get_field_values_handles_none_values(self):
        """Test _get_field_values handles None values correctly."""
        # Setup mock instance with None values
        self.mock_instance.content_type_id = None
        self.mock_instance.object_id = None

        # Call the method
        ct_id, pk_val = self.field._get_field_values(self.mock_instance)

        # Verify results
        assert ct_id is None
        assert pk_val is None

    def test_should_use_cached_object_returns_false_when_object_exists(self):
        """Test _should_use_cached_object returns False when rel_obj is not None."""
        mock_rel_obj = Mock()
        result = self.field._should_use_cached_object(self.mock_instance, mock_rel_obj, 123)
        assert result is False

    def test_should_use_cached_object_returns_false_when_not_cached(self):
        """Test _should_use_cached_object returns False when object is not cached."""
        with patch.object(self.field, 'is_cached', return_value=False):
            result = self.field._should_use_cached_object(self.mock_instance, None, 123)
        assert result is False

    def test_should_use_cached_object_handles_remote_object_case(self, foo_type):
        """Test _should_use_cached_object detects remote objects and returns False."""
        # Mock the field methods
        with patch.object(self.field, 'is_cached', return_value=True):
            with patch.object(self.field, 'get_content_type', return_value=foo_type):
                result = self.field._should_use_cached_object(self.mock_instance, None, 123)

        # Should return False for remote objects (don't use cache)
        assert result is False

    def test_should_use_cached_object_handles_local_object_case(self):
        """Test _should_use_cached_object returns True for local/shared objects."""
        from ansible_base.rbac.remote import get_local_resource_prefix

        # Mock a local content type
        mock_ct = Mock()
        mock_ct.service = get_local_resource_prefix()  # Use actual local prefix

        with patch.object(self.field, 'is_cached', return_value=True):
            with patch.object(self.field, 'get_content_type', return_value=mock_ct):
                result = self.field._should_use_cached_object(self.mock_instance, None, 123)

        # Should return True for local objects (use cache)
        assert result is True

    def test_should_use_cached_object_handles_shared_object_case(self):
        """Test _should_use_cached_object returns True for shared objects."""
        # Mock a shared content type
        mock_ct = Mock()
        mock_ct.service = "shared"

        with patch.object(self.field, 'is_cached', return_value=True):
            with patch.object(self.field, 'get_content_type', return_value=mock_ct):
                result = self.field._should_use_cached_object(self.mock_instance, None, 123)

        # Should return True for shared objects (use cache)
        assert result is True

    def test_should_use_cached_object_handles_none_ct_id(self):
        """Test _should_use_cached_object returns True when ct_id is None."""
        with patch.object(self.field, 'is_cached', return_value=True):
            result = self.field._should_use_cached_object(self.mock_instance, None, None)

        # Should return True when no content type (use cache)
        assert result is True

    def test_is_cached_object_valid_returns_false_for_none_object(self):
        """Test _is_cached_object_valid returns False when rel_obj is None."""
        result = self.field._is_cached_object_valid(None, 123, 456)
        assert result is False

    def test_is_cached_object_valid_returns_true_for_matching_object(self):
        """Test _is_cached_object_valid returns True when object matches."""
        mock_rel_obj = Mock()
        mock_rel_obj.pk = 456
        mock_ct = Mock()
        mock_ct.id = 123

        with patch.object(self.field, 'get_content_type', return_value=mock_ct):
            result = self.field._is_cached_object_valid(mock_rel_obj, 123, 456)

        assert result is True

    def test_is_cached_object_valid_returns_false_for_mismatched_ct(self):
        """Test _is_cached_object_valid returns False when content type doesn't match."""
        mock_rel_obj = Mock()
        mock_rel_obj.pk = 456
        mock_ct = Mock()
        mock_ct.id = 999  # Different content type ID

        with patch.object(self.field, 'get_content_type', return_value=mock_ct):
            result = self.field._is_cached_object_valid(mock_rel_obj, 123, 456)

        assert result is False

    def test_is_cached_object_valid_returns_false_for_mismatched_pk(self):
        """Test _is_cached_object_valid returns False when primary key doesn't match."""
        mock_rel_obj = Mock()
        mock_rel_obj.pk = 999  # Different primary key
        mock_ct = Mock()
        mock_ct.id = 123

        with patch.object(self.field, 'get_content_type', return_value=mock_ct):
            result = self.field._is_cached_object_valid(mock_rel_obj, 123, 456)

        assert result is False

    def test_fetch_related_object_returns_none_for_none_ct_id(self):
        """Test _fetch_related_object returns None when ct_id is None."""
        result = self.field._fetch_related_object(None, 456)
        assert result is None

    def test_fetch_related_object_handles_local_objects(self):
        """Test _fetch_related_object calls _fetch_local_object for local objects."""
        from ansible_base.rbac.remote import get_local_resource_prefix

        mock_ct = Mock()
        mock_ct.service = get_local_resource_prefix()  # Use actual local prefix
        mock_result = Mock()

        with patch.object(self.field, 'get_content_type', return_value=mock_ct):
            with patch.object(self.field, '_fetch_local_object', return_value=mock_result) as mock_fetch:
                result = self.field._fetch_related_object(123, 456)

        mock_fetch.assert_called_once_with(mock_ct, 456)
        assert result == mock_result

    def test_fetch_related_object_handles_shared_objects(self):
        """Test _fetch_related_object calls _fetch_local_object for shared objects."""
        mock_ct = Mock()
        mock_ct.service = "shared"
        mock_result = Mock()

        with patch.object(self.field, 'get_content_type', return_value=mock_ct):
            with patch.object(self.field, '_fetch_local_object', return_value=mock_result) as mock_fetch:
                result = self.field._fetch_related_object(123, 456)

        mock_fetch.assert_called_once_with(mock_ct, 456)
        assert result == mock_result

    def test_fetch_related_object_handles_remote_objects(self, foo_type):
        """Test _fetch_related_object creates RemoteObject for remote objects."""
        mock_result = Mock()

        with patch.object(self.field, 'get_content_type', return_value=foo_type):
            with patch.object(foo_type, 'get_object_for_this_type', return_value=mock_result) as mock_get:
                result = self.field._fetch_related_object(123, 456)

        mock_get.assert_called_once_with(pk=456)
        assert result == mock_result

    def test_fetch_local_object_returns_object_on_success(self):
        """Test _fetch_local_object returns object when found."""
        mock_ct = Mock()
        mock_result = Mock()
        mock_ct.get_object_for_this_type.return_value = mock_result

        result = self.field._fetch_local_object(mock_ct, 456)

        mock_ct.get_object_for_this_type.assert_called_once_with(pk=456)
        assert result == mock_result

    def test_fetch_local_object_returns_none_on_does_not_exist(self):
        """Test _fetch_local_object returns None when object doesn't exist."""
        mock_ct = Mock()
        mock_ct.get_object_for_this_type.side_effect = ObjectDoesNotExist()

        result = self.field._fetch_local_object(mock_ct, 456)

        assert result is None

    def test_fetch_local_object_returns_none_on_lookup_error(self):
        """Test _fetch_local_object returns None on LookupError."""
        mock_ct = Mock()
        mock_ct.get_object_for_this_type.side_effect = LookupError()

        result = self.field._fetch_local_object(mock_ct, 456)

        assert result is None


class TestFederatedForeignKeyIntegration:
    """Integration tests for the refactored __get__ method."""

    def test_get_method_integration_with_prefetch_fix(self, foo_type, foo_rd, rando):
        """Test that the refactored __get__ method properly handles prefetch_related bug."""
        # Create an assignment to a remote object
        remote_obj = RemoteObject(content_type=foo_type, object_id=42)
        assignment = foo_rd.give_permission(rando, remote_obj)
        assignment.refresh_from_db()

        # Simulate prefetch_related scenario
        qs = RoleUserAssignment.objects.filter(id=assignment.id).prefetch_related('content_object')
        assignment_with_prefetch = qs.first()

        # The refactored __get__ method should handle this correctly
        content_object = assignment_with_prefetch.content_object

        # Should recreate the RemoteObject, not return None
        assert content_object is not None
        assert isinstance(content_object, RemoteObject)
        assert content_object.object_id == '42'

    def test_get_method_integration_with_valid_cache(self, foo_type, foo_rd, rando):
        """Test that the refactored __get__ method uses valid cached objects."""
        # Create an assignment
        remote_obj = RemoteObject(content_type=foo_type, object_id=42)
        assignment = foo_rd.give_permission(rando, remote_obj)

        # Access content_object to populate cache
        first_access = assignment.content_object

        # Second access should use cache
        second_access = assignment.content_object

        # Should be the same object (cached)
        assert first_access is second_access
        assert isinstance(second_access, RemoteObject)

    def test_get_method_integration_with_none_ct_id(self):
        """Test that the refactored __get__ method handles None content_type_id."""
        # Create a mock assignment with no content type
        mock_assignment = Mock()
        mock_assignment._meta.get_field.return_value.attname = "content_type_id"
        mock_assignment.content_type_id = None
        mock_assignment.object_id = 42

        field = FederatedForeignKey()

        with patch.object(field, 'get_cached_value', return_value=None):
            with patch.object(field, 'is_cached', return_value=False):
                with patch.object(field, 'set_cached_value') as mock_set_cache:
                    result = field.__get__(mock_assignment)

        # Should return None for assignments with no content type
        assert result is None
        mock_set_cache.assert_called_once_with(mock_assignment, None)
