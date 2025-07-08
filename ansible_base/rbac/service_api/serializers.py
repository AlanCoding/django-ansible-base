from django.apps import apps
from rest_framework import serializers

from ..models import DABContentType, DABPermission, RoleDefinition, RoleTeamAssignment, RoleUserAssignment
from ..remote import RemoteObject


class DABContentTypeSerializer(serializers.ModelSerializer):
    parent_content_type = serializers.SlugRelatedField(read_only=True, slug_field='api_slug')

    class Meta:
        model = DABContentType
        fields = ['api_slug', 'service', 'app_label', 'model', 'parent_content_type', 'pk_field_type']


class DABPermissionSerializer(serializers.ModelSerializer):
    content_type = serializers.SlugRelatedField(read_only=True, slug_field='api_slug')

    class Meta:
        model = DABPermission
        fields = ['api_slug', 'codename', 'content_type', 'name']


class ActorAnsibleIDField(serializers.Field):
    def to_representation(self, actor):
        return str(actor.resource.ansible_id)

    def to_internal_value(self, data):
        resource_cls = apps.get_model('dab_resource_registry', 'Resource')
        try:
            resource = resource_cls.objects.get(ansible_id=data)
        except resource_cls.DoesNotExist:
            raise serializers.ValidationError(f"No {self.source} found with ansible_id={data}")

        return resource.content_object


assignment_common_fields = ('created', 'created_by_ansible_id', 'object_id', 'object_ansible_id', 'content_type', 'role_definition')


class BaseAssignmentSerializer(serializers.ModelSerializer):
    content_type = serializers.SlugRelatedField(read_only=True, slug_field='api_slug')
    role_definition = serializers.SlugRelatedField(slug_field='name', queryset=RoleDefinition.objects.all())
    created_by_ansible_id = ActorAnsibleIDField(source='created_by', required=False)
    object_ansible_id = serializers.SerializerMethodField()
    # TODO: use the from_service to control what we sync back to
    from_service = serializers.CharField(write_only=True)

    def get_created_by_ansible_id(self, obj):
        return str(obj.created_by.resource.ansible_id)

    def get_object_ansible_id(self, obj):
        content_object = obj.content_object
        if isinstance(content_object, RemoteObject):
            return None
        if hasattr(content_object, 'resource'):
            return str(content_object.resource.ansible_id)
        return None

    def find_existing_assignment(self, queryset):
        actor = self.validated_data[self.actor_field]
        object_id = self.validated_data['object_id']
        role_definition = self.validated_data['role_definition']
        return queryset.filter(object_id=object_id, role_definition=role_definition, **{self.actor_field: actor}).first()


class RoleUserAssignmentSerializer(BaseAssignmentSerializer):
    user_ansible_id = ActorAnsibleIDField(source='user', required=True)
    actor_field = 'user'

    class Meta:
        model = RoleUserAssignment
        fields = assignment_common_fields + ('user_ansible_id',)


class RoleTeamAssignmentSerializer(BaseAssignmentSerializer):
    team_ansible_id = ActorAnsibleIDField(source='team', required=True)
    actor_field = 'team'

    class Meta:
        model = RoleTeamAssignment
        fields = assignment_common_fields + ('team_ansible_id',)
