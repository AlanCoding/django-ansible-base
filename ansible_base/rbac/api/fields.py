from django.core.exceptions import ObjectDoesNotExist
from django.utils.functional import cached_property
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.fields import flatten_choices_dict, to_choices_dict

from ansible_base.rbac.permission_registry import permission_registry  # careful for circular imports


class ChoiceLikeMixin(serializers.ChoiceField):
    """
    This uses a ForeignKey to populate the choices of a choice field.
    This also manages some string manipulation, right now, adding the local service name.
    """

    default_error_messages = serializers.PrimaryKeyRelatedField.default_error_messages

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

    @cached_property
    def grouped_choices(self):
        self._initialize_choices()
        return self._grouped_choices

    @cached_property
    def choices(self):
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
    def __init__(self, **kwargs):
        kwargs['help_text'] = _('The type of resource this applies to')
        super().__init__(**kwargs)

    def get_resource_type_name(self, cls) -> str:
        return f"{permission_registry.get_resource_prefix(cls)}.{cls._meta.model_name}"

    def get_dynamic_choices(self):
        return list(sorted((self.get_resource_type_name(cls), cls._meta.verbose_name.title()) for cls in permission_registry.all_registered_models))

    def get_dynamic_object(self, data):
        model = data.rsplit('.')[-1]
        return permission_registry.content_type_model.objects.get(model=model)

    def to_representation(self, value):
        if isinstance(value, str):
            return value  # slight hack to work to AWX schema tests
        return self.get_resource_type_name(value.model_class())


class PermissionField(ChoiceLikeMixin):
    @property
    def service_prefix(self):
        if registry := permission_registry.get_resource_registry():
            return registry.api_config.service_type
        return 'local'

    def get_dynamic_choices(self):
        perms = []
        for cls in permission_registry.all_registered_models:
            cls_name = cls._meta.model_name
            for action in cls._meta.default_permissions:
                perms.append(f'{permission_registry.get_resource_prefix(cls)}.{action}_{cls_name}')
            for perm_name, description in cls._meta.permissions:
                perms.append(f'{permission_registry.get_resource_prefix(cls)}.{perm_name}')
        return list(sorted(perms))

    def get_dynamic_object(self, data):
        codename = data.rsplit('.')[-1]
        return permission_registry.permission_qs.get(codename=codename)

    def to_representation(self, value):
        if isinstance(value, str):
            return value  # slight hack to work to AWX schema tests
        ct = permission_registry.content_type_model.objects.get_for_id(value.content_type_id)  # optimization
        return f'{permission_registry.get_resource_prefix(ct.model_class())}.{value.codename}'


class ManyRelatedListField(serializers.ListField):
    def to_representation(self, data):
        "Adds the .all() to treat the value as a queryset"
        return [self.child.to_representation(item) if item is not None else None for item in data.all()]
