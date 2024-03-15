import logging

# Django
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.utils.translation import gettext_lazy as _

# Django-rest-framework
from rest_framework.exceptions import ValidationError

# ansible_base lib functions
from ansible_base.lib.abstract_models.common import CommonModel
from ansible_base.rbac.models.managers import RoleDefinitionManager
from ansible_base.rbac.models.permission import DABPermission

# ansible_base RBAC logic imports
from ansible_base.rbac.permission_registry import permission_registry
from ansible_base.rbac.validators import validate_assignment

logger = logging.getLogger('ansible_base.rbac.models')


class RoleDefinition(CommonModel):
    "Abstract definition of the permissions a role will grant before it is associated to an object"

    class Meta:
        app_label = 'dab_rbac'
        verbose_name_plural = _('role_definition')

    name = models.TextField(db_index=True, unique=True)
    description = models.TextField(blank=True)
    managed = models.BooleanField(default=False, editable=False)  # pulp definition of Role uses locked
    permissions = models.ManyToManyField('dab_rbac.DABPermission', related_name='role_definitions')
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

    @classmethod
    def user_assignment_model(cls):
        return cls._meta.get_field('user_assignments').related_model

    @classmethod
    def team_assignment_model(cls):
        return cls._meta.get_field('team_assignments').related_model

    @classmethod
    def object_role_model(cls):
        return cls._meta.get_field('object_roles').related_model

    def give_or_remove_global_permission(self, actor, giving=True):
        if self.content_type is not None:
            raise RuntimeError('Role definition content type must be null to assign globally')

        if actor._meta.model_name == 'user':
            if not settings.ANSIBLE_BASE_ALLOW_SINGLETON_USER_ROLES:
                raise ValidationError('Global roles are not enabled for users')
            kwargs = dict(object_role=None, user=actor, role_definition=self)
            cls = self.user_assignment_model()
        elif isinstance(actor, permission_registry.team_model):
            if not settings.ANSIBLE_BASE_ALLOW_SINGLETON_TEAM_ROLES:
                raise ValidationError('Global roles are not enabled for teams')
            kwargs = dict(object_role=None, team=actor, role_definition=self)
            cls = self.team_assignment_model()
        else:
            raise RuntimeError(f'Cannot give permission to {actor}, must be a user or team')

        if giving:
            assignment, _ = cls.objects.get_or_create(**kwargs)
        else:
            assignment = cls.objects.filter(**kwargs).first()
            if assignment:
                assignment.delete()

        # Clear any cached permissions
        if actor._meta.model_name == 'user':
            if hasattr(actor, '_singleton_permissions'):
                delattr(actor, '_singleton_permissions')
        else:
            # when team permissions change, users in memory may be affected by this
            # but there is no way to know what users, so we use a global flag
            from ansible_base.rbac.access_methods import bound_singleton_permissions

            bound_singleton_permissions._team_clear_signal = True

        return assignment

    def give_permission(self, actor, content_object):
        return self.give_or_remove_permission(actor, content_object, giving=True)

    def remove_permission(self, actor, content_object):
        return self.give_or_remove_permission(actor, content_object, giving=False)

    def give_or_remove_permission(self, actor, content_object, giving=True, sync_action=False):
        "Shortcut method to do whatever needed to give user or team these permissions"
        validate_assignment(self, actor, content_object)
        obj_ct = ContentType.objects.get_for_model(content_object)
        # sanitize the object_id to its database version, practically, remove "-" chars from uuids
        object_id = content_object._meta.pk.get_db_prep_value(content_object.pk, connection)
        kwargs = dict(role_definition=self, content_type=obj_ct, object_id=object_id)

        created = False
        object_role = self.object_role_model().objects.filter(**kwargs).first()
        if object_role is None:
            if not giving:
                return  # nothing to do
            object_role = self.object_role_model().objects.create(**kwargs)
            created = True

        from ansible_base.rbac.triggers import needed_updates_on_assignment, update_after_assignment

        update_teams, to_update = needed_updates_on_assignment(self, actor, object_role, created=created, giving=True)

        assignment = None
        if actor._meta.model_name == 'user':
            if giving:
                assignment, created = self.user_assignment_model().objects.get_or_create(user=actor, object_role=object_role)
            else:
                object_role.users.remove(actor)
        elif isinstance(actor, permission_registry.team_model):
            if giving:
                assignment, created = self.team_assignment_model().objects.get_or_create(team=actor, object_role=object_role)
            else:
                object_role.teams.remove(actor)

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

    @classmethod
    def user_global_permissions(cls, user, permission_qs=None):
        """Evaluation method only for global permissions from global roles

        This is special, in that it bypasses the RoleEvaluation table and methods.
        That is because global roles do not enumerate role permissions there,
        so global permissions are computed separately, here.
        """
        if permission_qs is None:
            # Allowing caller to replace the base permission set allows changing the type of thing returned
            # this is used in the assignment querysets, but these cases must call the method directly
            permission_qs = DABPermission.objects.all()

        perm_set = set()
        if settings.ANSIBLE_BASE_ALLOW_SINGLETON_USER_ROLES:
            rd_qs = cls.objects.filter(user_assignments__user=user, content_type=None)
            perm_qs = permission_qs.filter(role_definitions__in=rd_qs)
            perm_set.update(perm_qs)
        if settings.ANSIBLE_BASE_ALLOW_SINGLETON_TEAM_ROLES:
            # Users gain team membership via object roles that grant the teams member permission
            user_obj_roles = cls.object_role_model().objects.filter(users=user)
            user_teams_qs = permission_registry.team_model.objects.filter(member_roles__in=user_obj_roles)
            # Those teams (the user is in) then have a set of global roles they have been assigned
            rd_qs = cls.objects.filter(team_assignments__team__in=user_teams_qs, content_type=None)
            perm_qs = permission_qs.filter(role_definitions__in=rd_qs)
            perm_set.update(perm_qs)
        return perm_set

    def summary_fields(self):
        return {'id': self.id, 'name': self.name, 'description': self.description, 'managed': self.managed}
