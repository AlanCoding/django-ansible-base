from django.apps import apps
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.db.utils import IntegrityError
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied
from rest_framework.serializers import ValidationError

from ansible_base.lib.abstract_models.common import get_url_for_object
from ansible_base.lib.serializers.common import AbstractCommonModelSerializer, CommonModelSerializer, ImmutableCommonModelSerializer
from ansible_base.lib.utils.auth import get_team_model
from ansible_base.rbac.models import RoleDefinition, RoleTeamAssignment, RoleUserAssignment
from ansible_base.rbac.permission_registry import permission_registry  # careful for circular imports
from ansible_base.rbac.policies import check_content_obj_permission, visible_users
from ansible_base.rbac.validators import check_locally_managed, validate_permissions_for_model

from ..models import DABContentType, DABPermission, get_evaluation_model
from ..remote import RemoteObject


class RoleDefinitionSerializer(CommonModelSerializer):
    permissions = serializers.SlugRelatedField(
        slug_field='api_slug',
        queryset=DABPermission.objects.all(),
        many=True,
        error_messages={
            'does_not_exist': "Cannot use permission with api_slug '{value}', object does not exist",
            'invalid': "Each content type must be a valid slug string",
        },
    )
    content_type = serializers.SlugRelatedField(
        slug_field='api_slug',
        queryset=DABContentType.objects.all(),
        allow_null=True,  # for global roles
        default=None,
        error_messages={
            'does_not_exist': "Cannot use type with api_slug '{value}', object does not exist",
            'invalid': "Each content type must be a valid slug string",
        },
    )

    class Meta:
        model = RoleDefinition
        read_only_fields = ('id', 'summary_fields')
        fields = '__all__'

    def validate(self, validated_data):
        # Obtain the resultant new values
        if 'permissions' in validated_data:
            permissions = validated_data['permissions']
        else:
            permissions = list(self.instance.permissions.all())
        if 'content_type' in validated_data:
            content_type = validated_data['content_type']
        elif self.instance:
            content_type = self.instance.content_type
        validate_permissions_for_model(permissions, content_type)
        if getattr(self, 'instance', None):
            check_locally_managed(self.instance)
        return super().validate(validated_data)


class RoleDefinitionDetailSerializer(RoleDefinitionSerializer):
    content_type = serializers.SlugRelatedField(slug_field='api_slug', read_only=True)


class BaseAssignmentSerializer(CommonModelSerializer):
    content_type = serializers.SlugRelatedField(slug_field='api_slug', read_only=True)
    object_ansible_id = serializers.UUIDField(
        required=False,
        help_text=_('The resource id of the object this role applies to. An alternative to the object_id field.'),
        allow_null=True,  # for ease of use of the browseable API
    )

    def __init__(self, *args, **kwargs):
        """
        We want to allow ansible_id override of user and team fields
        but want to keep the non-null database constraint, so actor field is marked required=True here
        """
        super().__init__(*args, **kwargs)
        request = self.context.get('request')
        if request:
            qs = self.get_actor_queryset(request.user)
        else:
            qs = self.Meta.model._meta.get_field(self.actor_field).model.objects.all()
        self.fields[self.actor_field] = serializers.PrimaryKeyRelatedField(queryset=qs, required=False)

    def raise_id_fields_error(self, field1, field2):
        msg = _('Provide exactly one of %(actor_field)s or %(actor_field)s_ansible_id') % {'actor_field': self.actor_field}
        raise ValidationError({self.actor_field: msg, f'{self.actor_field}_ansible_id': msg})

    def get_by_ansible_id(self, ansible_id, requesting_user, for_field):
        try:
            resource_cls = apps.get_model('dab_resource_registry', 'Resource')
        except LookupError:
            raise ValidationError({for_field: _('Django-ansible-base resource registry must be installed to use ansible_id fields')})

        try:
            resource = resource_cls.objects.get(ansible_id=ansible_id)
            # Ensure that the request user has permission to view provided data
            obj = resource.content_object
            if obj._meta.model_name == 'user':
                if not visible_users(requesting_user).filter(pk=obj.pk).exists():
                    raise ObjectDoesNotExist
            elif not requesting_user.has_obj_perm(obj, 'view'):
                raise ObjectDoesNotExist
        except ObjectDoesNotExist:
            msg = serializers.PrimaryKeyRelatedField.default_error_messages['does_not_exist']
            raise ValidationError({for_field: msg.format(pk_value=ansible_id)})
        return resource.content_object

    def get_actor_from_data(self, validated_data, requesting_user):
        actor_aid_field = f'{self.actor_field}_ansible_id'
        if validated_data.get(self.actor_field) and validated_data.get(actor_aid_field):
            self.raise_id_fields_error(self.actor_field, actor_aid_field)
        elif validated_data.get(self.actor_field):
            actor = validated_data[self.actor_field]
        elif ansible_id := validated_data.get(actor_aid_field):
            actor = self.get_by_ansible_id(ansible_id, requesting_user, for_field=actor_aid_field)
        else:
            self.raise_id_fields_error(self.actor_field, f'{self.actor_field}_ansible_id')
        return actor

    def get_object_from_data(self, validated_data, role_definition, requesting_user):
        obj = None
        if validated_data.get('object_id') and validated_data.get('object_ansible_id'):
            self.raise_id_fields_error('object_id', 'object_ansible_id')
        elif validated_data.get('object_id'):
            if not role_definition.content_type:
                raise ValidationError({'object_id': _('System role does not allow for object assignment')})
            model = role_definition.content_type.model_class()
            if issubclass(model, RemoteObject):
                return model(content_type=role_definition.content_type, object_id=validated_data['object_id'])
            try:
                obj = serializers.PrimaryKeyRelatedField(queryset=model.access_qs(requesting_user)).to_internal_value(validated_data['object_id'])
            except ValidationError as exc:
                raise ValidationError({'object_id': exc.detail})
            except AttributeError:
                if not permission_registry.is_registered(model):
                    raise ValidationError({'role_definition': 'Given role definition is for a model not registered in the permissions system'})
                raise  # in this case no idea what went wrong
        elif validated_data.get('object_ansible_id'):
            obj = self.get_by_ansible_id(validated_data.get('object_ansible_id'), requesting_user, for_field='object_ansible_id')
            if permission_registry.content_type_model.objects.get_for_model(obj) != role_definition.content_type:
                raise ValidationError(
                    {
                        'object_ansible_id': _('Object type of %(model_name)s does not match role type of %(role_definition)s')
                        % {'model_name': obj._meta.model_name, 'role_definition': role_definition.content_type.model}
                    }
                )
        return obj

    def create(self, validated_data):
        rd = validated_data['role_definition']
        requesting_user = self.context['view'].request.user

        # Resolve actor - team or user
        actor = self.get_actor_from_data(validated_data, requesting_user)

        # Resolve object
        obj = self.get_object_from_data(validated_data, rd, requesting_user)

        # model-level callback to further validate the assignment
        # can be optionally implemented by the model
        # the callback should raise DRF exceptions directly if
        # necessary
        if getattr(obj, 'validate_role_assignment', None):
            obj.validate_role_assignment(actor, rd, requesting_user=requesting_user)

        # Return a 400 if the role is not managed locally
        check_locally_managed(rd)

        if rd.content_type:
            # Object role assignment
            if not obj:
                raise ValidationError({'object_id': _('Object must be specified for this role assignment')})

            check_content_obj_permission(requesting_user, obj)

            try:
                with transaction.atomic():
                    assignment = rd.give_permission(actor, obj)
            except IntegrityError:
                assignment = self.Meta.model.objects.get(role_definition=rd, object_id=obj.pk, **{self.actor_field: actor})
        else:
            # Global role assignment, only allowed by superuser
            if not requesting_user.is_superuser:
                raise PermissionDenied

            with transaction.atomic():
                assignment = rd.give_global_permission(actor)

        return assignment

    def _get_related(self, obj) -> dict[str, str]:
        related = super()._get_related(obj)
        content_obj = obj.content_object
        if content_obj:
            if related_url := get_url_for_object(content_obj):
                related['content_object'] = related_url
        return related

    def _get_summary_fields(self, obj) -> dict[str, dict]:
        summary_fields = super()._get_summary_fields(obj)
        content_obj = obj.content_object
        if content_obj and hasattr(content_obj, 'summary_fields'):
            summary_fields['content_object'] = content_obj.summary_fields()
        return summary_fields


ASSIGNMENT_FIELDS = ImmutableCommonModelSerializer.Meta.fields + ['content_type', 'object_id', 'object_ansible_id', 'role_definition']


class RoleUserAssignmentSerializer(BaseAssignmentSerializer):
    actor_field = 'user'
    user_ansible_id = serializers.UUIDField(
        required=False,
        help_text=_('The resource ID of the user who will receive permissions from this assignment. An alternative to user field.'),
        allow_null=True,  # for ease of use of the browseable API
    )

    class Meta:
        model = RoleUserAssignment
        fields = ASSIGNMENT_FIELDS + ['user', 'user_ansible_id']

    def get_actor_queryset(self, requesting_user):
        return visible_users(requesting_user)


class RoleTeamAssignmentSerializer(BaseAssignmentSerializer):
    actor_field = 'team'
    team_ansible_id = serializers.UUIDField(
        required=False,
        help_text=_('The resource ID of the team who will receive permissions from this assignment. An alternative to team field.'),
    )

    class Meta:
        model = RoleTeamAssignment
        fields = ASSIGNMENT_FIELDS + ['team', 'team_ansible_id']

    def get_actor_queryset(self, requesting_user):
        return permission_registry.team_model.access_qs(requesting_user)


class RoleMetadataSerializer(serializers.Serializer):
    allowed_permissions = serializers.DictField(help_text=_('A List of permissions allowed for a role definition, given its content type.'))


class AccessListMixin(AbstractCommonModelSerializer):
    role_assignments = serializers.SerializerMethodField()

    @staticmethod
    def summarize_role_definition(role_definition):
        return {"name": role_definition.name, "url": get_url_for_object(role_definition)}

    def get_role_assignments(self, actor):
        obj = self.context.get("related_object")
        permission = self.context.get("permission")
        ct = self.context.get("content_type")

        assignment_list = []

        evaluation_cls = get_evaluation_model(obj)
        reverse_name = evaluation_cls._meta.get_field('role').remote_field.name
        if permission:
            obj_eval_qs = evaluation_cls.objects.filter(codename=permission.codename, object_id=obj.pk, content_type_id=ct.id)
        else:
            # All relevant assignments for the object
            obj_eval_qs = evaluation_cls.objects.filter(object_id=obj.pk, content_type_id=ct.id)
        obj_assignment_qs = actor.role_assignments.filter(**{f'object_role__{reverse_name}__in': obj_eval_qs})

        team_ct = DABContentType.objects.get_for_model(get_team_model())

        for assignment in obj_assignment_qs.distinct():
            if assignment.content_type_id == team_ct.pk:
                perm_type = "team"
            elif assignment.content_type_id == ct.pk:
                perm_type = "direct"
            else:
                perm_type = "indirect"
            assignment_list.append({"type": perm_type, "role_definition": self.summarize_role_definition(assignment.role_definition)})

        if permission:
            global_assignment_qs = actor.role_assignments.filter(content_type=None, role_definition__permissions=permission)
        else:
            global_assignment_qs = actor.role_assignments.filter(content_type=None, role_definition__permissions__content_type=ct)

        for assignment in global_assignment_qs.distinct():
            assignment_list.append({"type": "global", "role_definition": self.summarize_role_definition(assignment.role_definition)})

        return assignment_list


class UserAccessListMixin(AccessListMixin):
    _expected_fields = ['username', 'role_assignments']


class TeamAccessListMixin(AccessListMixin):
    _expected_fields = ['name', 'organization', 'role_assignments']
