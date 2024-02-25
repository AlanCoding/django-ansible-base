from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.db.utils import IntegrityError
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied
from rest_framework.fields import flatten_choices_dict, to_choices_dict

from ansible_base.lib.abstract_models.common import get_url_for_object
from ansible_base.lib.serializers.common import CommonModelSerializer
from ansible_base.rbac.models import RoleDefinition, RoleTeamAssignment, RoleUserAssignment
from ansible_base.rbac.permission_registry import permission_registry  # careful for circular imports
from ansible_base.rbac.validators import validate_permissions_for_model


class ChoiceLikeMixin(serializers.ChoiceField):
    """
    This uses a ForeignKey to populate the choices of a choice field.
    This also manages some string manipulation, right now, adding the local service name.
    """

    default_error_messages = serializers.PrimaryKeyRelatedField.default_error_messages
    psuedo_field = None  # define in subclass

    def get_model_for_init(self):
        "Delay any model references until serializer initialization due to load order concerns"
        raise NotImplementedError

    def get_dynamic_choices(self):
        raise NotImplementedError

    def get_dynamic_object(self, data):
        raise NotImplementedError

    def to_representation(self, value):
        raise NotImplementedError

    def __init__(self, **kwargs):
        # Workaround so that the parent class does not resolve the choices right away
        self.html_cutoff = kwargs.pop('html_cutoff', self.html_cutoff)
        self.html_cutoff_text = kwargs.pop('html_cutoff_text', self.html_cutoff_text)

        self.allow_blank = kwargs.pop('allow_blank', False)
        super(serializers.ChoiceField, self).__init__(**kwargs)

    def _initialize_choices(self):
        choices = self.get_dynamic_choices()
        self._grouped_choices = to_choices_dict(choices)
        self._choices = flatten_choices_dict(self._grouped_choices)
        self.choice_strings_to_values = {str(k): k for k in self._choices}

    @property
    def grouped_choices(self):
        if not hasattr(self, '_grouped_choices'):
            self._initialize_choices()
        return self._grouped_choices

    @property
    def choices(self):
        if not hasattr(self, '_choices'):
            self._initialize_choices()
        return self._choices

    def to_internal_value(self, data):
        try:
            return self.get_dynamic_object(data)
        except ObjectDoesNotExist:
            self.fail('does_not_exist', pk_value=data)
        except (TypeError, ValueError):
            self.fail('incorrect_type', data_type=type(data).__name__)


class ContentTypeField(ChoiceLikeMixin):
    psuedo_field = 'model'

    def __init__(self, **kwargs):
        kwargs['help_text'] = _('The type of resource this applies to')
        super().__init__(**kwargs)

    def get_model_for_init(self):
        return permission_registry.content_type_model

    def get_dynamic_choices(self):
        return [
            (f'{settings.ANSIBLE_BASE_SERVICE_PREFIX}.{cls._meta.model_name}', cls._meta.verbose_name.title())
            for cls in permission_registry.all_registered_models
        ]

    def get_dynamic_object(self, data):
        model = data.rsplit('.')[-1]
        return permission_registry.content_type_model.objects.get(model=model)

    def to_representation(self, value):
        return f'{settings.ANSIBLE_BASE_SERVICE_PREFIX}.{value.model}'


class PermissionField(ChoiceLikeMixin):
    psuedo_field = 'codename'

    def get_model_for_init(self):
        return permission_registry.permission_model

    def get_dynamic_choices(self):
        perms = []
        for cls in permission_registry.all_registered_models:
            cls_name = cls._meta.model_name
            for action in cls._meta.default_permissions:
                perms.append(f'{settings.ANSIBLE_BASE_SERVICE_PREFIX}.{action}_{cls_name}')
            for perm_name, description in cls._meta.permissions:
                perms.append(f'{settings.ANSIBLE_BASE_SERVICE_PREFIX}.{perm_name}')
        return perms

    def get_dynamic_object(self, data):
        codename = data.rsplit('.')[-1]
        return permission_registry.permission_model.objects.get(codename=codename)

    def to_representation(self, value):
        return f'{settings.ANSIBLE_BASE_SERVICE_PREFIX}.{value.codename}'


class ManyRelatedListField(serializers.ListField):
    def to_representation(self, data):
        "Adds the .all() to treat the value as a queryset"
        return [self.child.to_representation(item) if item is not None else None for item in data.all()]


class RoleDefinitionSerializer(CommonModelSerializer):
    # Relational versions - we may switch to these if custom permission and type models are exposed but out of scope here
    # permissions = serializers.SlugRelatedField(many=True, slug_field='codename', queryset=permission_registry.permission_model.objects.all())
    # content_type = ContentTypeField(slug_field='model', queryset=permission_registry.content_type_model.objects.all(), allow_null=True, default=None)
    permissions = ManyRelatedListField(child=PermissionField())
    content_type = ContentTypeField(allow_null=True, default=None)

    class Meta:
        model = RoleDefinition
        fields = '__all__'

    def validate(self, validated_data):
        validate_permissions_for_model(validated_data.get('permissions', []), validated_data.get('content_type'))
        return super().validate(validated_data)


class RoleDefinitionDetailSeraizler(RoleDefinitionSerializer):
    content_type = ContentTypeField(read_only=True)


class BaseAssignmentSerializer(CommonModelSerializer):
    content_type = ContentTypeField(read_only=True)

    def create(self, validated_data):
        rd = validated_data['role_definition']
        model = rd.content_type.model_class()
        obj = model.objects.get(pk=validated_data['object_id'])

        # validate user has permission
        actor = validated_data[self.actor_field]
        requesting_user = self.context['view'].request.user
        if not requesting_user.has_obj_perm(obj, 'change'):
            raise PermissionDenied

        try:
            with transaction.atomic():
                assignment = rd.give_permission(actor, obj)
        except IntegrityError:
            assignment = self.Meta.model.objects.get(role_definition=rd, object_id=obj.pk, **{self.actor_field: actor})

        return assignment

    def _get_related(self, obj):
        related = super()._get_related(obj)
        content_obj = obj.content_object
        if related_url := get_url_for_object(content_obj):
            related['content_object'] = related_url
        return related

    def _get_summary_fields(self, obj):
        summary_fields = super()._get_summary_fields(obj)
        content_obj = obj.content_object
        if content_obj and hasattr(content_obj, 'summary_fields'):
            summary_fields['content_object'] = content_obj.summary_fields()
        return summary_fields


class RoleUserAssignmentSerializer(BaseAssignmentSerializer):
    actor_field = 'user'

    class Meta:
        model = RoleUserAssignment
        fields = '__all__'


class RoleTeamAssignmentSerializer(BaseAssignmentSerializer):
    actor_field = 'team'

    class Meta:
        model = RoleTeamAssignment
        fields = '__all__'
