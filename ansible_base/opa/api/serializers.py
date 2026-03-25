import logging

from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from ansible_base.opa.models import GroupRoleAssignment, OPAGroup, Policy, Role
from ansible_base.opa.registry import opa_registry

logger = logging.getLogger(__name__)


class PolicySerializer(serializers.ModelSerializer):
    class Meta:
        model = Policy
        fields = [
            "id",
            "role",
            "resource",
            "action",
            "field_name",
            "operator",
            "value_type",
            "constant_value",
            "position",
            "created",
            "modified",
        ]
        read_only_fields = ["id", "created", "modified"]

    def validate(self, attrs):
        # Build a transient Policy to run model-level validation
        instance = self.instance or Policy()
        for k, v in attrs.items():
            setattr(instance, k, v)

        from ansible_base.opa.validators import validate_policy

        try:
            validate_policy(instance)
        except Exception as e:
            raise ValidationError({"detail": str(e)})

        return attrs


class PolicyInlineSerializer(PolicySerializer):
    """Serializer for policies nested inside a Role."""

    class Meta(PolicySerializer.Meta):
        fields = [f for f in PolicySerializer.Meta.fields if f != "role"]
        read_only_fields = ["id", "created", "modified"]


class RoleSerializer(serializers.ModelSerializer):
    policies = PolicyInlineSerializer(many=True, read_only=True)

    class Meta:
        model = Role
        fields = [
            "id",
            "name",
            "description",
            "managed",
            "created_by",
            "policies",
            "created",
            "modified",
        ]
        read_only_fields = ["id", "created_by", "created", "modified"]

    def validate_managed(self, value):
        if self.instance and self.instance.managed and not value:
            raise ValidationError("Cannot unset managed flag on a managed role.")
        return value


class RoleDetailSerializer(RoleSerializer):
    """Used for update to prevent changing name on managed roles."""

    def validate(self, attrs):
        if self.instance and self.instance.managed:
            if "name" in attrs and attrs["name"] != self.instance.name:
                raise ValidationError({"name": "Cannot rename a managed role."})
        return attrs


class OPAGroupSerializer(serializers.ModelSerializer):
    users = serializers.PrimaryKeyRelatedField(
        many=True,
        read_only=True,
    )

    class Meta:
        model = OPAGroup
        fields = [
            "id",
            "name",
            "organization",
            "users",
            "managed",
            "created",
            "modified",
        ]
        read_only_fields = ["id", "created", "modified"]

    def validate_managed(self, value):
        if self.instance and self.instance.managed and not value:
            raise ValidationError("Cannot unset managed flag on a managed group.")
        return value


class OPAGroupMembershipSerializer(serializers.Serializer):
    """Serializer for adding/removing users from a group."""

    user_id = serializers.IntegerField()


class GroupRoleAssignmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupRoleAssignment
        fields = [
            "id",
            "group",
            "role",
            "created",
            "modified",
        ]
        read_only_fields = ["id", "created", "modified"]


class UserEffectiveScopeSerializer(serializers.Serializer):
    """Read-only serializer for user effective scope introspection."""

    resource = serializers.CharField()
    action = serializers.CharField()
    allow = serializers.BooleanField()
    clauses = serializers.ListField(child=serializers.DictField())
