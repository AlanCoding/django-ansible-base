# CRUM for getting the requesting user
from crum import get_current_user

# Django
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.utils.translation import gettext_lazy as _

# ansible_base lib functions
from ansible_base.lib.abstract_models.common import CommonModel
from ansible_base.rbac.models.object_role import ObjectRoleFields


class AssignmentBase(CommonModel, ObjectRoleFields):
    """
    This uses some parts of CommonModel to save metadata like documenting
    the user who assigned the permission and timestamp when it happened.
    This caches ObjectRole fields for purposes of serializers,
    both models are immutable, making caching easy.
    """

    object_role = models.ForeignKey('dab_rbac.ObjectRole', on_delete=models.CASCADE, editable=False, null=True)
    object_id = models.TextField(
        null=True, blank=True, help_text=_('Primary key of the object this assignment applies to, null value indicates system-wide assignment')
    )
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, null=True)
    modified = None
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
        # skip over CommonModel save because it would error due to missing modified_by and created
        return super(CommonModel, self).save(*args, **kwargs)


class RoleUserAssignment(AssignmentBase):
    role_definition = models.ForeignKey(
        "dab_rbac.RoleDefinition",
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

    @property
    def actor(self):
        "Really simple helper to give same behavior between user and role assignments"
        return self.user


class RoleTeamAssignment(AssignmentBase):
    role_definition = models.ForeignKey(
        "dab_rbac.RoleDefinition",
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

    @property
    def actor(self):
        "Really simple helper to give same behavior between user and role assignments"
        return self.team
