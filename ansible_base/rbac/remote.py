from typing import Type

from django.db import models
from django.conf import settings
from django.utils.module_loading import import_string


"""
This module has utilities related to processing of remote objects.
Those are, objects that exist on other systems,
but permissions for objects in that system are tracked here.
In this case, the objects do not exist locally,
and the users and teams are assumed to be synchronized.

Even if this feature is not being used, this code will still be used.
Because for consistency, in every case the project name will need to be set.
This module will be the source of truth for things like the projet name.
"""

def get_resource_registry():
    """Resource registry is another DAB app, and this returns its registry."""
    if 'ansible_base.resource_registry' not in settings.INSTALLED_APPS:
        return None

    # Extremely risky situation around circular imports
    from ansible_base.resource_registry.registry import get_registry

    return get_registry()


def get_local_resource_prefix() -> str:
    """The API project designator for unshared objects local to this service.

    Unless otherwise defined by the resource registry config,
    this is the project field & API prefix that all Django models should set.
    """
    if registry := get_resource_registry():
        return registry.api_config.service_type
    return 'local'


def get_resource_prefix(cls: models.Model) -> str:
    """The API project designator for given cls, according to the resource registry

    This is used for related slug references, like "awx.inventory" to reference
    The inventory model under the service known as awx.
    """
    if registry := get_resource_registry():
        # duplicates logic in ansible_base/resource_registry/apps.py
        try:
            resource_config = registry.get_config_for_model(cls)
            if resource_config.managed_serializer:
                return "shared"  # shared model
        except KeyError:
            pass  # unregistered model

        # Fallback for unregistered and non-shared models
        return registry.api_config.service_type
    else:
        return 'local'


class RemoteObject:
    """Placeholder for objects that live in another project."""

    def __init__(self, content_type, object_id):
        self.content_type = content_type
        self.object_id = object_id

    def __repr__(self):
        return f"<RemoteObject {self.content_type} id={self.object_id}>"


def get_remote_object_class() -> Type[RemoteObject]:
    """Return the class which represents remote objects.

    This is for further ORM-level customization of remote object handling.
    More specifically, if you use the DAB RBAC objects, but create your own view.
    This would add properties to the assignment.content_object in the case of remote objects.
    """
    remote_cls = getattr(settings, 'RBAC_REMOTE_OBJECT_CLASS', None)
    if remote_cls:
        return import_string(remote_cls)
    return RemoteObject
