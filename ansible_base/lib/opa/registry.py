import logging
import os

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)

VALID_OPERATORS = {"eq"}
VALID_VALUE_TYPES = {"constant", "principal_user_id"}

REQUIRED_FIELD_KEYS = {"django_path", "type", "operators"}
REQUIRED_RESOURCE_KEYS = {"model", "actions"}


def _validate_field_def(field_name, field_def, context):
    """Validate a single field definition dict."""
    missing = REQUIRED_FIELD_KEYS - set(field_def.keys())
    if missing:
        raise ImproperlyConfigured(f"DAB_OPA {context} field '{field_name}' missing keys: {missing}")

    if not isinstance(field_def["operators"], list):
        raise ImproperlyConfigured(f"DAB_OPA {context} field '{field_name}' operators must be a list")

    invalid_ops = set(field_def["operators"]) - VALID_OPERATORS
    if invalid_ops:
        raise ImproperlyConfigured(f"DAB_OPA {context} field '{field_name}' has invalid operators: {invalid_ops}")


class OPARegistry:
    """Loads and validates the DAB_OPA settings at startup.

    Provides lookup methods for resources, actions, and fields
    used by policy validation and Rego generation.
    """

    def __init__(self):
        self._config = None
        self._validated = False

    @property
    def config(self):
        if self._config is None:
            self._config = getattr(settings, "DAB_OPA", None)
            if self._config is None:
                raise ImproperlyConfigured("DAB_OPA setting is not defined.")
        return self._config

    @property
    def server_url(self):
        return getattr(
            settings,
            "DAB_OPA_SERVER_URL",
            os.environ.get("DAB_OPA_SERVER_URL", "http://localhost:8181"),
        )

    @property
    def transition_validation(self):
        return getattr(settings, "DAB_OPA_TRANSITION_VALIDATION", False)

    @property
    def strict_mode_default(self):
        return self.config.get("strict_mode_default", False)

    @property
    def shared_fields(self):
        return self.config.get("shared_fields", {})

    @property
    def resources(self):
        return self.config.get("resources", {})

    def get_resource(self, resource_name):
        """Return a resource definition or raise."""
        try:
            return self.resources[resource_name]
        except KeyError:
            raise ValueError(f"Unknown resource: '{resource_name}'. Valid resources: {list(self.resources.keys())}")

    def get_actions(self, resource_name):
        """Return valid actions for a resource."""
        return self.get_resource(resource_name)["actions"]

    def get_fields(self, resource_name):
        """Return merged fields (resource-specific + shared) for a resource."""
        resource_def = self.get_resource(resource_name)
        merged = dict(self.shared_fields)
        merged.update(resource_def.get("fields", {}))
        return merged

    def get_field(self, resource_name, field_name):
        """Return a field definition or raise."""
        fields = self.get_fields(resource_name)
        try:
            return fields[field_name]
        except KeyError:
            raise ValueError(
                f"Unknown field '{field_name}' for resource '{resource_name}'. "
                f"Valid fields: {list(fields.keys())}"
            )

    def get_action_dependencies(self, resource_name):
        """Return action dependency mapping for a resource."""
        resource_def = self.get_resource(resource_name)
        return resource_def.get("action_dependencies", {})

    def get_model(self, resource_name, apps=None):
        """Resolve the Django model class for a resource."""
        resource_def = self.get_resource(resource_name)
        model_path = resource_def["model"]
        if apps:
            return apps.get_model(model_path)
        from django.apps import apps as django_apps

        return django_apps.get_model(model_path)

    def validate(self, apps):
        """Validate the entire DAB_OPA configuration at startup."""
        if self._validated:
            return

        config = self.config

        # Validate shared_fields
        for field_name, field_def in self.shared_fields.items():
            _validate_field_def(field_name, field_def, "shared_fields")

        # Validate each resource
        for resource_name, resource_def in self.resources.items():
            missing = REQUIRED_RESOURCE_KEYS - set(resource_def.keys())
            if missing:
                raise ImproperlyConfigured(
                    f"DAB_OPA resource '{resource_name}' missing keys: {missing}"
                )

            # Validate model exists
            model_path = resource_def["model"]
            try:
                apps.get_model(model_path)
            except LookupError:
                raise ImproperlyConfigured(
                    f"DAB_OPA resource '{resource_name}' refers to model "
                    f"'{model_path}' that has not been installed."
                )

            # Validate actions is a list
            if not isinstance(resource_def["actions"], list) or not resource_def["actions"]:
                raise ImproperlyConfigured(
                    f"DAB_OPA resource '{resource_name}' actions must be a non-empty list."
                )

            # Validate resource-specific fields
            for field_name, field_def in resource_def.get("fields", {}).items():
                _validate_field_def(field_name, field_def, f"resource '{resource_name}'")

            # Validate action_dependencies reference valid actions
            for action, deps in resource_def.get("action_dependencies", {}).items():
                if action not in resource_def["actions"]:
                    raise ImproperlyConfigured(
                        f"DAB_OPA resource '{resource_name}' action_dependencies "
                        f"references unknown action '{action}'."
                    )
                if not isinstance(deps, list):
                    raise ImproperlyConfigured(
                        f"DAB_OPA resource '{resource_name}' action_dependencies "
                        f"for '{action}' must be a list."
                    )
                for dep in deps:
                    if dep not in resource_def["actions"]:
                        raise ImproperlyConfigured(
                            f"DAB_OPA resource '{resource_name}' action_dependencies: "
                            f"'{action}' depends on unknown action '{dep}'."
                        )

        self._validated = True
        logger.info(
            "DAB_OPA registry validated: %d resources, %d shared fields",
            len(self.resources),
            len(self.shared_fields),
        )


opa_registry = OPARegistry()
