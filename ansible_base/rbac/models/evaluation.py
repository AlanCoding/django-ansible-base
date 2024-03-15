from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.utils.translation import gettext_lazy as _


class RoleEvaluationMeta:
    app_label = 'dab_rbac'
    verbose_name_plural = _('role_object_permissions')
    indexes = [
        models.Index(fields=["role", "content_type_id", "object_id"]),  # used by get_roles_on_resource
        models.Index(fields=["role", "content_type_id", "codename"]),  # used by accessible_objects
    ]
    constraints = [models.UniqueConstraint(name='one_entry_per_object_permission_and_role', fields=['object_id', 'content_type_id', 'codename', 'role'])]


# COMPUTED DATA
class RoleEvaluationFields(models.Model):
    """
    Cached data that shows what permissions an ObjectRole gives its owners
    example:
        ObjectRole 423 gives users execute access to job template 37

    RoleAncestorEntry model in old AWX RBAC system is a direct analog

    This is used to make permission evaluations via querysets returning object ids
    the data in this table is created from the ObjectRole and RoleDefinition data
      you should not interact with this table yourself
      the only method that should ever write to this table is
        compute_object_role_permissions()

    In the above example, "ObjectRole 423" may be a role that grants membership
    to a team, and that team was given permission to another ObjectRole.
    """

    class Meta:
        abstract = True

    def __str__(self):
        return (
            f'{self._meta.verbose_name.title()}(pk={self.id}, codename={self.codename}, object_id={self.object_id}, '
            f'content_type_id={self.content_type_id}, role_id={self.role_id})'
        )

    def save(self, *args, **kwargs):
        if self.id:
            raise RuntimeError(f'{self._meta.model_name} model is immutable and only used internally')
        return super().save(*args, **kwargs)

    codename = models.TextField(null=False, help_text=_("The name of the permission, giving the action and the model, from the Django Permission model"))
    # NOTE: we do not form object_id and content_type into a content_object, following from AWX practice
    # this can be relaxed as we have comparative performance testing to confirm doing so does not affect permissions
    content_type_id = models.PositiveIntegerField(null=False)

    def obj_perm_id(self):
        "Used for in-memory hashing of the type of object permission this represents"
        return (self.codename, self.content_type_id, self.object_id)

    @classmethod
    def accessible_ids(cls, model_cls, actor, codename, content_types=None):
        """
        Corresponds to AWX accessible_pk_qs

        Use instead of `MyModel.objects` when you want to only consider
        resources that a user has specific permissions for. For example:
        MyModel.accessible_objects(user, 'view_mymodel').filter(name__istartswith='bar')

        Intended to be used for users, but should also be valid for teams
        """
        # We only have a content_types exception for multiple content types for polymorphic models
        # for normal models you should not need it, but AWX unified_ models need it to get by
        filter_kwargs = dict(role__in=actor.has_roles.all(), codename=codename)
        if content_types:
            filter_kwargs['content_type_id__in'] = content_types
        else:
            filter_kwargs['content_type_id'] = ContentType.objects.get_for_model(model_cls).id
        return cls.objects.filter(**filter_kwargs).values_list('object_id').distinct()

    @classmethod
    def accessible_objects(cls, model_cls, user, codename):
        return model_cls.objects.filter(pk__in=cls.accessible_ids(model_cls, user, codename))

    @classmethod
    def get_permissions(cls, user, obj):
        """
        Returns permissions that a user has to obj from object-roles,
        does not consider permissions from user flags or system-wide roles
        """
        return cls.objects.filter(role__in=user.has_roles.all(), content_type_id=ContentType.objects.get_for_model(obj).id, object_id=obj.id).values_list(
            'codename', flat=True
        )

    @classmethod
    def has_obj_perm(cls, user, obj, codename) -> bool:
        """
        Note this behaves similar in function to the REST Framework has_object_permission
        method on permission classes, but it is named differently to avoid unintentionally conflicting
        """
        return cls.objects.filter(
            role__in=user.has_roles.all(), content_type_id=ContentType.objects.get_for_model(obj).id, object_id=obj.pk, codename=codename
        ).exists()


class RoleEvaluation(RoleEvaluationFields):
    class Meta(RoleEvaluationMeta):
        pass

    role = models.ForeignKey(
        "dab_rbac.ObjectRole",
        null=False,
        on_delete=models.CASCADE,
        related_name='permission_partials',
        help_text=_("The object role that grants this form of permission"),
    )
    object_id = models.PositiveIntegerField(null=False)


class RoleEvaluationUUID(RoleEvaluationFields):
    "Cache for UUID type models"

    class Meta(RoleEvaluationMeta):
        constraints = [
            models.UniqueConstraint(name='one_entry_per_object_permission_and_role_uuid', fields=['object_id', 'content_type_id', 'codename', 'role'])
        ]

    role = models.ForeignKey(
        "dab_rbac.ObjectRole",
        null=False,
        on_delete=models.CASCADE,
        related_name='permission_partials_uuid',
        help_text=_("The object role that grants this form of permission"),
    )
    object_id = models.UUIDField(null=False)


def get_evaluation_model(cls):
    pk_field = cls._meta.pk
    # For proxy models, including django-polymorphic, use the id field from parent table
    if isinstance(pk_field, models.OneToOneField):
        pk_field = pk_field.remote_field.model._meta.pk

    if isinstance(pk_field, models.IntegerField):
        return RoleEvaluation
    elif isinstance(pk_field, models.UUIDField):
        return RoleEvaluationUUID
    else:
        raise RuntimeError(f'Model {cls._meta.model_name} primary key type of {pk_field} is not supported')
