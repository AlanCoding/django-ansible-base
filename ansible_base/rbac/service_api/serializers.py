from django.apps import apps
from rest_framework import serializers

from ..models import DABContentType, DABPermission, RoleTeamAssignment, RoleUserAssignment
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


assignment_common_fields = ('created', 'created_by_ansible_id', 'object_id', 'object_ansible_id', 'content_type', 'role_definition')


class BaseAssignmentSerializer(serializers.ModelSerializer):
    content_type = serializers.SlugRelatedField(read_only=True, slug_field='api_slug')
    role_definition = serializers.SlugRelatedField(read_only=True, slug_field='name')
    created_by_ansible_id = serializers.SerializerMethodField()
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
        actor_ansible_id = self.validated_data[f'{self.actor_field}_ansible_id']
        object_id = self.validated_data['object_id']
        role_definition = self.validated_data['role_definition']

        resource_cls = apps.get_model('dab_resource_registry', 'Resource')
        actor_resource = resource_cls.objects.get(ansible_id=actor_ansible_id)
        actor = actor_resource.content_object
        return queryset.filter(object_id=object_id, role_definition=role_definition, **{self.actor_field: actor}).first()


class RoleUserAssignmentSerializer(BaseAssignmentSerializer):
    user_ansible_id = serializers.SerializerMethodField()
    actor_field = 'user'

    class Meta:
        model = RoleUserAssignment
        fields = assignment_common_fields + ('user_ansible_id',)

    def get_user_ansible_id(self, obj):
        return str(obj.user.resource.ansible_id)


class RoleTeamAssignmentSerializer(BaseAssignmentSerializer):
    user_ansible_id = serializers.SerializerMethodField()
    actor_field = 'team'

    class Meta:
        model = RoleTeamAssignment
        fields = assignment_common_fields + ('team_ansible_id',)

    def get_team_ansible_id(self, obj):
        return str(obj.team.resource.ansible_id)
