from django.apps import apps
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.db.utils import IntegrityError
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied
from rest_framework.serializers import ValidationError

from ansible_base.lib.abstract_models.common import get_url_for_object
from ansible_base.lib.serializers.common import CommonModelSerializer, ImmutableCommonModelSerializer
from ansible_base.rbac.api.fields import ContentTypeField, ManyRelatedListField, PermissionField
from ansible_base.rbac.models import RoleDefinition, RoleTeamAssignment, RoleUserAssignment
from ansible_base.rbac.permission_registry import permission_registry  # careful for circular imports
from ansible_base.rbac.policies import check_content_obj_permission, visible_users
from ansible_base.rbac.validators import check_locally_managed, validate_permissions_for_model


class RoleDefinitionSerializer(CommonModelSerializer):
    # Relational versions - we may switch to these if custom permission and type models are exposed but out of scope here
    # permissions = serializers.SlugRelatedField(many=True, slug_field='codename', queryset=DABPermission.objects.all())
    # content_type = ContentTypeField(slug_field='model', queryset=permission_registry.content_type_model.objects.all(), allow_null=True, default=None)
    permissions = ManyRelatedListField(child=PermissionField())
    content_type = ContentTypeField(allow_null=True, default=None)

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
        else:
            content_type = self.instance.content_type
        validate_permissions_for_model(permissions, content_type)
        check_locally_managed(permissions)
        return super().validate(validated_data)


class RoleDefinitionDetailSerializer(RoleDefinitionSerializer):
    content_type = ContentTypeField(read_only=True)


class BaseAssignmentSerializer(CommonModelSerializer):
    content_type = ContentTypeField(read_only=True)
    object_ansible_id = serializers.UUIDField(
        required=False,
        help_text=_('Resource id of the object this role applies to. Alternative to the object_id field.'),
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
            try:
                obj = serializers.PrimaryKeyRelatedField(queryset=model.access_qs(requesting_user)).to_internal_value(validated_data['object_id'])
            except ValidationError as exc:
                raise ValidationError({'object_id': exc.detail})
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
            obj.validate_role_assignment(actor, rd)

        if rd.content_type:
            # Object role assignment
            if not obj:
                raise ValidationError({'object_id': _('Object must be specified for this role assignment')})

            check_content_obj_permission(requesting_user, obj)
            check_locally_managed(rd.permissions.prefetch_related('content_type'))

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
        help_text=_('Resource id of the user who will receive permissions from this assignment. Alternative to user field.'),
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
        help_text=_('Resource id of the team who will receive permissions from this assignment. Alternative to team field.'),
    )

    class Meta:
        model = RoleTeamAssignment
        fields = ASSIGNMENT_FIELDS + ['team', 'team_ansible_id']

    def get_actor_queryset(self, requesting_user):
        return permission_registry.team_model.access_qs(requesting_user)
