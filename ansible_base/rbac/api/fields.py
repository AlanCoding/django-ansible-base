from django.apps import apps
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import serializers


class ActorAnsibleIdField(serializers.UUIDField):
    """
    UUID field that serializes actor objects to their ansible_id and accepts ansible_id for deserialization.

    Always resolves ansible_id input to the corresponding actor object.
    Uses the source parameter to determine which field to populate.
    """

    def to_representation(self, actor):
        """Convert actor object to its ansible_id UUID"""
        if actor is None:
            return None
        try:
            if hasattr(actor, 'resource') and actor.resource:
                return super().to_representation(actor.resource.ansible_id)
        except ObjectDoesNotExist:
            # Resource doesn't exist, return None
            pass
        return None

    def to_internal_value(self, data):
        """Convert ansible_id UUID to actor object"""
        if data is None:
            return None

        # Let UUIDField handle validation and conversion
        uuid_value = super().to_internal_value(data)

        # Always resolve to actor object
        resource_cls = apps.get_model('dab_resource_registry', 'Resource')
        try:
            resource = resource_cls.objects.get(ansible_id=uuid_value)
        except resource_cls.DoesNotExist:
            source_name = getattr(self, 'source', 'actor')
            raise serializers.ValidationError(f"No {source_name} found with ansible_id={uuid_value}")
        return resource.content_object
