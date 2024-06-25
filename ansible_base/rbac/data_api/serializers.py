from collections import OrderedDict

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.reverse import reverse

from ansible_base.lib.serializers.common import AbstractCommonModelSerializer, CommonModelSerializer
from ansible_base.lib.utils.auth import get_team_model
from ansible_base.rbac.models import ObjectRole, RoleDefinition, RoleEvaluation, RoleEvaluationUUID, RoleUserAssignment, RoleTeamAssignment
from ansible_base.rbac.validators import permissions_allowed_for_role


class RoleMetadataSerializer(serializers.Serializer):
    allowed_permissions = serializers.DictField(help_text=_('List of permissions allowed for a role definition, given its content type.'))


class RoleDefinitionRefSerializer(serializers.ModelSerializer):
    class Meta:
        model = RoleDefinition
        fields = ('id', 'name', 'managed')


class TeamRefSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_team_model()
        fields = ('name', 'organization', 'description')


class UserInfoSerializer(serializers.ModelSerializer):
    system_permissions = serializers.SerializerMethodField(method_name='get_system_permissions')
    object_permissions = serializers.SerializerMethodField(method_name='get_object_permissions')

    class Meta:
        model = get_user_model()
        fields = ('id', 'username', 'is_superuser', 'system_permissions', 'object_permissions')

    def get_system_permissions(self, user):
        return user.singleton_permissions()

    def get_object_permissions(self, user):
        codename_set = set()
        for evaluation_cls in (RoleEvaluation, RoleEvaluationUUID):
            codename_set |= set(evaluation_cls.objects.filter(role__users=user).values_list('codename', flat=True).distinct())
        return list(codename_set)


class UserRefSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = (
            'id',
            'username',
            'is_superuser',
        )


class UserAssignmentSerializer(serializers.ModelSerializer):
    role_definition = RoleDefinitionRefSerializer(read_only=True)
    user = UserRefSerializer(read_only=True)

    class Meta:
        model = RoleUserAssignment
        fields = ('id', 'role_definition', 'user')


class TeamAssignmentSerializer(serializers.ModelSerializer):
    role_definition = RoleDefinitionRefSerializer(read_only=True)
    team = TeamRefSerializer(read_only=True)

    class Meta:
        model = RoleTeamAssignment
        fields = ('id', 'role_definition', 'team')


class DontCallItObjectRoleSerializer(CommonModelSerializer):
    """Object roles are not formally surfaced or supported through the API

    The model here is object role, but details of the direct object are hidden"""

    role_definition = RoleDefinitionRefSerializer(read_only=True)
    users = UserRefSerializer(many=True, read_only=True)
    teams = TeamRefSerializer(many=True, read_only=True)

    class Meta:
        model = ObjectRole
        abstract = True
        fields = ('users', 'teams', 'role_definition')
        depth = 1


class GenericObjectSerializer(AbstractCommonModelSerializer):
    object_roles = DontCallItObjectRoleSerializer(many=True, read_only=True)
    user_permissions = serializers.SerializerMethodField(method_name='get_user_permissions')
    url = serializers.SerializerMethodField(method_name='get_url')

    class Meta:
        abstract = True
        fields = ('url', 'related', 'pk', 'object_roles', 'user_permissions')

    def get_url(self, obj):
        view = self.context['view']
        return reverse('rbacobject-detail', kwargs={'model_name': view.kwargs['model_name'], 'object_id': obj.pk})

    def get_user_permissions(self, obj):
        data = OrderedDict()
        for codename in self.context['object_codenames']:
            data[codename] = getattr(obj, f'can_{codename}')
        return data

    def _get_related(self, obj):
        data = OrderedDict()
        view = self.context['view']
        data['user_access'] = reverse('rbacuserassignment-list', kwargs={'model_name': view.kwargs['model_name'], 'object_id': obj.pk})
        return data


class ContentTypeSerializer(AbstractCommonModelSerializer):
    object_permissions = serializers.SerializerMethodField(method_name='get_object_permissions')
    child_permissions = serializers.SerializerMethodField(method_name='get_child_permissions')

    class Meta:
        model = ContentType
        fields = '__all__'

    def _get_related(self, obj):
        data = OrderedDict()
        data['objects'] = reverse('rbacobject-list', kwargs={'model_name': obj.model})
        return data

    def get_url(self, obj):
        return reverse('rbactype-detail', kwargs={'model_name': obj.model})

    def get_object_permissions(self, obj):
        return self.context['view']._object_codenames(obj.model_class())

    def get_child_permissions(self, obj):
        model_cls = obj.model_class()
        data = permissions_allowed_for_role(model_cls)
        data.pop(model_cls)
        print_data = OrderedDict()
        for cls, codenames in data.items():
            print_data[cls._meta.model_name] = codenames
        return print_data
