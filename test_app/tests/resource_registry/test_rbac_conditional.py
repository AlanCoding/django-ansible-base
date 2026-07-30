"""
Test suite to verify resource_registry works with rbac installed.
Conditional rbac-not-installed tests are only on devel (requires guards not present on 2.6).
"""

import pytest

from ansible_base.resource_registry.constants import (
    SHARED_ORGANIZATION_RESOURCE_TYPE,
    SHARED_ROLE_DEFINITION_RESOURCE_TYPE,
    SHARED_TEAM_RESOURCE_TYPE,
    SHARED_USER_RESOURCE_TYPE,
)
from ansible_base.resource_registry.registry import ServiceAPIConfig
from ansible_base.resource_registry.rest_client import ResourceAPIClient
from ansible_base.resource_registry.shared_types import LenientPermissionSlugListField, RoleDefinitionType


class TestResourceRegistryWithRBAC:
    """Test resource registry functionality when rbac IS installed (normal case)."""

    def test_resource_api_client_rbac_methods_work(self):
        """Test that RBAC methods work when rbac is available."""
        # This test runs with rbac installed (default test environment)
        client = ResourceAPIClient("http://test", "/test/")

        # These should not raise RuntimeError (though they may raise other errors due to network/auth)
        # We're just testing that the conditional check passes
        try:
            client.list_role_types()
        except RuntimeError as e:
            if "requires ansible_base.rbac to be installed" in str(e):
                pytest.fail("Should not raise rbac requirement error when rbac is installed")
        except Exception:
            # Other exceptions (network, auth, etc.) are expected and OK
            pass

    def test_role_definition_type_works(self):
        """Test that RoleDefinitionType works when rbac is available."""
        # Should not raise RuntimeError about rbac requirement
        try:
            serializer = RoleDefinitionType()
            # Should have content_type field when rbac is available
            assert 'content_type' in serializer.fields
        except RuntimeError as e:
            if "requires ansible_base.rbac to be installed" in str(e):
                pytest.fail("Should not raise rbac requirement error when rbac is installed")

    def test_lenient_permission_slug_list_field_works(self):
        """Test that LenientPermissionSlugListField works when rbac is available."""
        field = LenientPermissionSlugListField()

        # Should not raise RuntimeError about rbac requirement
        # (though it may raise other validation errors)
        try:
            field.to_internal_value([])
        except RuntimeError as e:
            if "requires ansible_base.rbac to be installed" in str(e):
                pytest.fail("Should not raise rbac requirement error when rbac is installed")
        except Exception:
            # Other exceptions (validation, etc.) are expected and OK
            pass

    def test_service_api_config_includes_role_definition_processor(self):
        """Test that ServiceAPIConfig includes RoleDefinitionProcessor when rbac is available."""
        processors = ServiceAPIConfig._default_resource_processors

        # Should include shared.roledefinition when rbac is installed
        assert SHARED_ROLE_DEFINITION_RESOURCE_TYPE in processors

        # Should also include other processors
        assert SHARED_USER_RESOURCE_TYPE in processors
        assert SHARED_TEAM_RESOURCE_TYPE in processors
        assert SHARED_ORGANIZATION_RESOURCE_TYPE in processors


class TestResourceRegistryConditionalImports:
    """Test the conditional import behavior directly."""

    def test_imports_work_with_rbac(self):
        """Test that conditional imports work when rbac is available."""
        # These imports should work without errors
        from ansible_base.resource_registry import registry, rest_client, shared_types
        from ansible_base.resource_registry.tasks import sync

        # All modules should be importable
        assert rest_client is not None
        assert shared_types is not None
        assert sync is not None
        assert registry is not None
