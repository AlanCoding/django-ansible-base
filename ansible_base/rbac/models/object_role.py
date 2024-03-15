import logging

# Django
from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.db.models.functions import Cast
from django.utils.translation import gettext_lazy as _

# ansible_base RBAC logic imports
from ansible_base.lib.utils.models import is_add_perm
from ansible_base.rbac.models.evaluation import RoleEvaluation, RoleEvaluationUUID
from ansible_base.rbac.models.role_definition import RoleDefinition
from ansible_base.rbac.permission_registry import permission_registry
from ansible_base.rbac.prefetch import TypesPrefetch

logger = logging.getLogger('ansible_base.rbac.models')


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
        # NOTE: type casting is necessary in postgres but not sqlite3
        object_id_field = cls._meta.get_field('object_id')
        obj_filter = models.Q(object_id__in=permission_qs.values_list(Cast('object_id', output_field=object_id_field)))

        if not hasattr(user, '_singleton_permission_objs'):
            user._singleton_permission_objs = RoleDefinition.user_global_permissions(user)

        if user._singleton_permission_objs:
            super_ct_ids = set(perm.content_type_id for perm in user._singleton_permission_objs)
            # content_type=None condition: A good-enough rule - you can see other global assignments if you have any yourself
            return cls.objects.filter(obj_filter | models.Q(content_type__in=super_ct_ids) | models.Q(content_type=None))
        return cls.objects.filter(obj_filter)

    @classmethod
    def visible_items(cls, user):
        "This ORs querysets to show assignments to both UUID and integer pk models"
        return cls._visible_items(RoleEvaluation, user) | cls._visible_items(RoleEvaluationUUID, user)

    @property
    def cache_id(self):
        "The ObjectRole GenericForeignKey is text, but cache needs to match models"
        return RoleEvaluation._meta.get_field('object_id').to_python(self.object_id)


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
        role_model = role_content_type.model_class()
        # ObjectRole.object_id is stored as text, we convert it to the model pk native type
        object_id = role_model._meta.pk.to_python(self.object_id)
        for permission in types_prefetch.permissions_for_object_role(self):
            permission_content_type = types_prefetch.get_content_type(permission.content_type_id)

            # direct object permission
            if permission.content_type_id == self.content_type_id:
                expected_evaluations.add((permission.codename, self.content_type_id, object_id))
                continue

            # add child permission on the parent object, usually only for add permission
            if is_add_perm(permission.codename) or settings.ANSIBLE_BASE_CACHE_PARENT_PERMISSIONS:
                expected_evaluations.add((permission.codename, self.content_type_id, object_id))

            # add child object permission on child objects
            # Only propogate add permission to children which are parents of the permission model
            filter_path = None
            child_model = None
            if is_add_perm(permission.codename):
                for path, model in permission_registry.get_child_models(role_model):
                    if '__' in path and model._meta.model_name == permission_content_type.model:
                        path_to_parent, filter_path = path.split('__', 1)
                        child_model = permission_content_type.model_class()._meta.get_field(path_to_parent).related_model
                        eval_ct = ContentType.objects.get_for_model(child_model).id
                if not child_model:
                    continue
            else:
                for path, model in permission_registry.get_child_models(role_model):
                    if model._meta.model_name == permission_content_type.model:
                        filter_path = path
                        child_model = model
                        eval_ct = permission.content_type_id
                        break
                else:
                    logger.warning(f'{self.role_definition} listed {permission.codename} but model is not a child, ignoring')
                    continue

            # fetching child objects of an organization is very performance sensitive
            # for multiple permissions of same type, make sure to only do query once
            id_list = []
            if eval_ct in cached_id_lists:
                id_list = cached_id_lists[eval_ct]
            else:
                id_list = child_model.objects.filter(**{filter_path: object_id}).values_list('pk', flat=True)
                cached_id_lists[eval_ct] = list(id_list)

            for id in id_list:
                expected_evaluations.add((permission.codename, eval_ct, id))
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
