import logging

# CRUM for getting the requesting user
from crum import get_current_user

# Django
from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

# ansible_base lib functions
from ansible_base.lib.abstract_models.common import CommonModel

# ansible_base RBAC logic imports
from ansible_base.rbac.permission_registry import permission_registry
from ansible_base.rbac.prefetch import TypesPrefetch
from ansible_base.rbac.validators import validate_permissions_for_model

logger = logging.getLogger('ansible_base.rbac.models')


class RoleDefinitionManager(models.Manager):
    def give_creator_permissions(self, user, obj):
        # If the user is a superuser, no need to bother giving the creator permissions
        for super_flag in settings.ANSIBLE_BASE_BYPASS_SUPERUSER_FLAGS:
            if getattr(user, super_flag):
                return True

        needed_actions = settings.ANSIBLE_BASE_CREATOR_DEFAULTS

        needed_perms = set()
        for perm in permission_registry.permission_model.objects.filter(content_type=ContentType.objects.get_for_model(obj)):
            action = perm.codename.split('_', 1)[0]
            if action in needed_actions:
                needed_perms.add(perm.codename)

        has_permissions = set(RoleEvaluation.get_permissions(user, obj))
        has_permissions.update(user.singleton_permissions())
        if set(needed_perms) - set(has_permissions):
            rd, _ = self.get_or_create(
                permissions=needed_perms, name=f'{obj._meta.model_name}-creator-permission', defaults={'content_type': ContentType.objects.get_for_model(obj)}
            )

            rd.give_permission(user, obj)

    def get_or_create(self, permissions=(), defaults=None, **kwargs):
        "Add extra feature on top of existing get_or_create to use permissions list"
        if permissions:
            permissions = set(permissions)
            for existing_rd in self.prefetch_related('permissions'):
                existing_set = set(perm.codename for perm in existing_rd.permissions.all())
                if existing_set == permissions:
                    return (existing_rd, False)
            create_kwargs = kwargs.copy()
            if defaults:
                create_kwargs.update(defaults)
            return (self.create_from_permissions(permissions=permissions, **create_kwargs), True)
        return super().get_or_create(defaults=defaults, **kwargs)

    def create_from_permissions(self, permissions=(), **kwargs):
        "Create from a list of text-type permissions and do validation"
        perm_list = [permission_registry.permission_model.objects.get(codename=str_perm) for str_perm in permissions]

        ct = kwargs.get('content_type', None)
        if kwargs.get('content_type_id', None):
            ct = ContentType.objects.get(id=kwargs['content_type_id'])

        validate_permissions_for_model(perm_list, ct)

        rd = self.create(**kwargs)
        rd.permissions.add(*perm_list)
        return rd


class RoleDefinition(CommonModel):
    "Abstract definition of the permissions a role will grant before it is associated to an object"

    class Meta:
        app_label = 'dab_rbac'
        verbose_name_plural = _('role_definition')

    name = models.TextField(db_index=True, unique=True)
    description = models.TextField(blank=True)
    managed = models.BooleanField(default=False, editable=False)  # pulp definition of Role uses locked
    permissions = models.ManyToManyField(settings.ANSIBLE_BASE_PERMISSION_MODEL)
    content_type = models.ForeignKey(
        ContentType,
        help_text=_('Type of resource this can apply to, only used for validation and user assistance'),
        null=True,
        default=None,
        on_delete=models.CASCADE,
    )

    objects = RoleDefinitionManager()
    router_basename = 'roledefinition'
    ignore_relations = ['permissions', 'object_roles', 'teams', 'users']

    def __str__(self):
        managed_str = ''
        if self.managed:
            managed_str = ', managed=True'
        return f'RoleDefinition(pk={self.id}, name={self.name}{managed_str})'

    def give_global_permission(self, actor):
        return self.give_or_remove_global_permission(actor, giving=True)

    def remove_global_permission(self, actor):
        return self.give_or_remove_global_permission(actor, giving=False)

    def give_or_remove_global_permission(self, actor, giving=True):
        if actor._meta.model_name == 'user':
            rel = settings.ANSIBLE_BASE_SINGLETON_USER_RELATIONSHIP
            if not rel:
                raise RuntimeError('No global role relationship configured for users')
        elif isinstance(actor, permission_registry.team_model):
            rel = settings.ANSIBLE_BASE_SINGLETON_TEAM_RELATIONSHIP
            if not rel:
                raise RuntimeError('No global role relationship configured for users')
        else:
            raise RuntimeError(f'Cannot give permission to {actor}, must be a user or team')

        manager = getattr(actor, rel)
        if giving:
            manager.add(self)
        else:
            manager.remove(self)

        # Clear any cached permissions, if applicable
        if hasattr(actor, '_singleton_permissions'):
            delattr(actor, '_singleton_permissions')

    def give_permission(self, actor, content_object):
        return self.give_or_remove_permission(actor, content_object, giving=True)

    def remove_permission(self, actor, content_object):
        return self.give_or_remove_permission(actor, content_object, giving=False)

    def give_or_remove_permission(self, actor, content_object, giving=True, sync_action=False):
        "Shortcut method to do whatever needed to give user or team these permissions"
        obj_ct = ContentType.objects.get_for_model(content_object)
        # sanitize the object_id to its database version, practically, remove "-" chars from uuids
        object_id = content_object._meta.pk.get_db_prep_value(content_object.id, connection)
        kwargs = dict(role_definition=self, content_type=obj_ct, object_id=object_id)

        created = False
        object_role = ObjectRole.objects.filter(**kwargs).first()
        if object_role is None:
            if not giving:
                return  # nothing to do
            object_role = ObjectRole.objects.create(**kwargs)
            created = True

        from ansible_base.rbac.triggers import needed_updates_on_assignment, update_after_assignment

        update_teams, to_update = needed_updates_on_assignment(self, actor, object_role, created=created, giving=True)

        assignment = None
        if actor._meta.model_name == 'user':
            if giving:
                assignment, created = RoleUserAssignment.objects.get_or_create(user=actor, object_role=object_role)
            else:
                object_role.users.remove(actor)
        elif isinstance(actor, permission_registry.team_model):
            if giving:
                assignment, created = RoleTeamAssignment.objects.get_or_create(team=actor, object_role=object_role)
            else:
                object_role.teams.remove(actor)
        else:
            raise RuntimeError(f'Cannot give permission to {actor}, must be a user or team')

        if (not giving) and (not (object_role.users.exists() or object_role.teams.exists())):
            if object_role in to_update:
                to_update.remove(object_role)
            object_role.delete()

        update_after_assignment(update_teams, to_update)

        if not sync_action and self.name in permission_registry._trackers:
            tracker = permission_registry._trackers[self.name]
            with tracker.sync_active():
                tracker.sync_relationship(actor, content_object, giving=giving)

        return assignment

    def summary_fields(self):
        return {'id': self.id, 'name': self.name, 'description': self.description, 'managed': self.managed}


class ObjectRoleFields(models.Model):
    "Fields for core functionality of object-roles"

    class Meta:
        abstract = True

    # role_definition set on child models to set appropriate help_text and related_name
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.TextField(null=False)
    content_object = GenericForeignKey('content_type', 'object_id')

    @classmethod
    def _visible_items(cls, eval_cls, user):
        permission_qs = eval_cls.objects.filter(
            role__in=user.has_roles.all(),
            content_type_id=models.OuterRef('content_type_id'),
        )
        return cls.objects.filter(object_id__in=permission_qs.values('object_id'))

    @classmethod
    def visible_items(cls, user):
        "This ORs querysets to show assignments to both UUID and integer pk models"
        return cls._visible_items(RoleEvaluation, user) | cls._visible_items(RoleEvaluationUUID, user)

    @property
    def cache_id(self):
        "The ObjectRole GenericForeignKey is text, but cache needs to match models"
        return RoleEvaluation._meta.get_field('object_id').to_python(self.object_id)


class AssignmentBase(CommonModel, ObjectRoleFields):
    """
    This uses some parts of CommonModel to save metadata like documenting
    the user who assigned the permission and timestamp when it happened.
    This caches ObjectRole fields for purposes of serializers,
    both models are immutable, making caching easy.
    """

    object_role = models.ForeignKey('dab_rbac.ObjectRole', on_delete=models.CASCADE, editable=False)
    modified_on = None
    created_on = models.DateTimeField(
        default=timezone.now,  # Needed to work in migrations as a through field, which CommonModel can not do
        editable=False,
        help_text="The date/time this resource was created",
    )
    modified_by = None

    class Meta:
        app_label = 'dab_rbac'
        abstract = True

    def __init__(self, *args, **kwargs):
        """
        Because through models are created via a bulk_create, the save method is usually not called
        to get around this, we populate the user model after initialization
        """
        super().__init__(*args, **kwargs)
        if not self.id:
            user = get_current_user()
            if user:
                # Hazard: user can be a SimpleLazyObject, so use id
                self.created_by_id = user.id
        # Cache fields from the associated object_role
        if self.object_role_id and not self.object_id:
            self.object_id = self.object_role.object_id
            self.content_type_id = self.object_role.content_type_id
            self.role_definition_id = self.object_role.role_definition_id

    def save(self, *args, **kwargs):
        if self.id:
            raise RuntimeError(f'{self._meta.verbose_name.title()} model is immutable, use RoleDefinition.give_permission method')
        # skip over CommonModel save because it would error due to missing modified_by and created_on
        return super(CommonModel, self).save(*args, **kwargs)


class RoleUserAssignment(AssignmentBase):
    role_definition = models.ForeignKey(
        RoleDefinition,
        on_delete=models.CASCADE,
        help_text=_("The role definition which defines permissions conveyed by this assignment"),
        related_name='user_assignments',
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    router_basename = 'roleuserassignment'

    class Meta:
        app_label = 'dab_rbac'
        unique_together = ('user', 'object_role')

    def __repr__(self):
        return f'RoleUserAssignment(pk={self.id})'


class RoleTeamAssignment(AssignmentBase):
    role_definition = models.ForeignKey(
        RoleDefinition,
        on_delete=models.CASCADE,
        help_text=_("The role definition which defines permissions conveyed by this assignment"),
        related_name='team_assignments',
    )
    team = models.ForeignKey(settings.ANSIBLE_BASE_TEAM_MODEL, on_delete=models.CASCADE)
    router_basename = 'roleteamassignment'

    class Meta:
        app_label = 'dab_rbac'
        unique_together = ('team', 'object_role')

    def __repr__(self):
        return f'RoleTeamAssignment(pk={self.id})'


class ObjectRole(ObjectRoleFields):
    """
    This is the successor to the Role model in the old AWX RBAC system
    It is renamed to ObjectRole to distinguish from the abstract or generic
    RoleDefinition which does not apply to a particular object.

    This matches the RoleDefinition to a content_object.
    After this is created, users and teams can be added to gives those
    permissions to that user or team, for that content_object
    """

    class Meta:
        app_label = 'dab_rbac'
        verbose_name_plural = _('object_roles')
        indexes = [models.Index(fields=["content_type", "object_id"])]
        ordering = ("content_type", "object_id")
        constraints = [models.UniqueConstraint(name='one_object_role_per_object_and_role', fields=['object_id', 'content_type', 'role_definition'])]

    role_definition = models.ForeignKey(
        RoleDefinition,
        on_delete=models.CASCADE,
        help_text=_("The role definition which defines what permissions this object role grants"),
        related_name='object_roles',
    )
    users = models.ManyToManyField(
        to=settings.AUTH_USER_MODEL,
        through='dab_rbac.RoleUserAssignment',
        through_fields=("object_role", "user"),
        related_name='has_roles',
        help_text=_("Users who have access to the permissions defined by this object role"),
    )
    teams = models.ManyToManyField(
        to=settings.ANSIBLE_BASE_TEAM_MODEL,
        through='dab_rbac.RoleTeamAssignment',
        through_fields=("object_role", "team"),
        related_name='has_roles',
        help_text=_("Teams or groups who have access to the permissions defined by this object role"),
    )
    # COMPUTED DATA
    provides_teams = models.ManyToManyField(
        settings.ANSIBLE_BASE_TEAM_MODEL,
        related_name='member_roles',
        editable=False,
        help_text=_("Users who have this role obtain member access to these teams, and inherit all their permissions"),
    )

    def __str__(self):
        return f'ObjectRole(pk={self.id}, {self.content_type.model}={self.object_id})'

    def save(self, *args, **kwargs):
        if self.id:
            raise RuntimeError('ObjectRole model is immutable, use RoleDefinition.give_permission method')
        return super().save(*args, **kwargs)

    def summary_fields(self):
        return {'id': self.id}

    def descendent_roles(self):
        "Returns a set of roles that you implicitly have if you have this role"
        descendents = set()
        for target_team in self.provides_teams.all():
            # the roles that offer these permissions could change as a result of adding teams
            descendents.update(set(target_team.has_roles.all()))
        return descendents

    def expected_direct_permissions(self, types_prefetch=None):
        expected_evaluations = set()
        cached_id_lists = {}
        if not types_prefetch:
            types_prefetch = TypesPrefetch()
        role_content_type = types_prefetch.get_content_type(self.content_type_id)
        for permission in types_prefetch.permissions_for_object_role(self):
            permission_content_type = types_prefetch.get_content_type(permission.content_type_id)

            if permission.content_type_id == self.content_type_id:  # direct object permission
                model = permission_content_type.model_class()
                # ObjectRole.object_id is stored as text, we convert it to the model pk native type
                object_id = model._meta.pk.to_python(self.object_id)
                expected_evaluations.add((permission.codename, self.content_type_id, object_id))
            elif permission.codename.startswith('add'):
                model = permission_content_type.model_class()
                role_child_models = set(cls for filter_path, cls in permission_registry.get_child_models(role_content_type.model))
                if model not in role_child_models:
                    # NOTE: this should also be validated when creating a role definition
                    logger.warning(f'{self} lists {permission.codename} for an object that is not a child object')
                    continue
                object_id = role_content_type.model_class()._meta.pk.to_python(self.object_id)
                expected_evaluations.add((permission.codename, self.content_type_id, object_id))
            else:  # child object permission
                id_list = []
                object_id = role_content_type.model_class()._meta.pk.to_python(self.object_id)
                # fetching child objects of an organization is very performance sensitive
                # for multiple permissions of same type, make sure to only do query once
                if permission.content_type_id in cached_id_lists:
                    id_list = cached_id_lists[permission.content_type_id]
                else:
                    # model must be in same app as organization
                    for filter_path, model in permission_registry.get_child_models(role_content_type.model):
                        if model._meta.model_name == permission_content_type.model:
                            id_list = model.objects.filter(**{filter_path: object_id}).values_list('pk', flat=True)
                            cached_id_lists[permission.content_type_id] = list(id_list)
                            break
                    else:
                        logger.warning(f'{self.role_definition} listed {permission.codename} but model is not a child, ignoring')
                        continue

                for id in id_list:
                    expected_evaluations.add((permission.codename, permission.content_type_id, id))
                if settings.ANSIBLE_BASE_CACHE_PARENT_PERMISSIONS:
                    expected_evaluations.add((permission.codename, self.content_type_id, object_id))
        return expected_evaluations

    def needed_cache_updates(self, types_prefetch=None):
        existing_partials = dict()
        for permission_partial in self.permission_partials.all():
            existing_partials[permission_partial.obj_perm_id()] = permission_partial
        for permission_partial in self.permission_partials_uuid.all():
            existing_partials[permission_partial.obj_perm_id()] = permission_partial

        expected_evaluations = self.expected_direct_permissions(types_prefetch)

        for team in self.provides_teams.all():
            for team_role in team.has_roles.all():
                expected_evaluations.update(team_role.expected_direct_permissions(types_prefetch))

        existing_set = set(existing_partials.keys())

        to_delete = set()
        for identifier in existing_set - expected_evaluations:
            to_delete.add((existing_partials[identifier].id, type(identifier[-1])))

        to_add = []
        for codename, ct_id, obj_pk in expected_evaluations - existing_set:
            to_add.append(RoleEvaluation(codename=codename, content_type_id=ct_id, object_id=obj_pk, role=self))

        return (to_delete, to_add)


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
    def has_obj_perm(cls, user, obj, codename):
        """
        Note this behaves similar in function to the REST Framework has_object_permission
        method on permission classes, but it is named differently to avoid unintentionally conflicting
        """
        return cls.objects.filter(
            role__in=user.has_roles.all(), content_type_id=ContentType.objects.get_for_model(obj).id, object_id=obj.id, codename=codename
        ).exists()


class RoleEvaluation(RoleEvaluationFields):
    class Meta(RoleEvaluationMeta):
        pass

    role = models.ForeignKey(
        ObjectRole, null=False, on_delete=models.CASCADE, related_name='permission_partials', help_text=_("The object role that grants this form of permission")
    )
    object_id = models.PositiveIntegerField(null=False)


class RoleEvaluationUUID(RoleEvaluationFields):
    "Cache for UUID type models"

    class Meta(RoleEvaluationMeta):
        constraints = [
            models.UniqueConstraint(name='one_entry_per_object_permission_and_role_uuid', fields=['object_id', 'content_type_id', 'codename', 'role'])
        ]

    role = models.ForeignKey(
        ObjectRole,
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
