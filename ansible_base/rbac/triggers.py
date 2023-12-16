import logging

from django.apps import apps
from django.conf import settings
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db.models.signals import m2m_changed, post_delete, post_init, post_save, pre_delete
from django.db.utils import ProgrammingError

from ansible_base.migrations._managed_definitions import setup_managed_role_definitions
from ansible_base.models.rbac import ObjectRole, RoleDefinition, RoleEvaluation
from ansible_base.rbac.caching import compute_object_role_permissions, compute_team_member_roles
from ansible_base.rbac.permission_registry import permission_registry

logger = logging.getLogger('ansible_base.rbac.triggers')


'''
As the caching module will fill in cached data,
this module shall manage the calling of the caching methods.
Sounds simple, but is actually more complicated that the caching logic itself.
'''


def team_ancestor_roles(team):
    """
    Return a queryset of all roles that directly or indirectly grant any form of permission to a team.
    This is generally used when invalidating a team membership for one reason or another.
    """
    return set(
        ObjectRole.objects.filter(
            permission_partials__in=RoleEvaluation.objects.filter(
                codename=permission_registry.team_permission, object_id=team.id, content_type_id=ContentType.objects.get_for_model(team).id
            )
        )
    )


def validate_assignment_enabled(actor, content_type, has_team_perm=False):
    team_team_allowed = settings.ROLE_TEAM_TEAM_ALLOWED
    team_org_allowed = settings.ROLE_TEAM_ORG_ALLOWED
    team_org_team_allowed = settings.ROLE_TEAM_ORG_TEAM_ALLOWED

    if all([team_team_allowed, team_org_allowed, team_org_team_allowed]):
        return  # Everything is allowed
    team_model_name = permission_registry.team_model._meta.model_name
    if actor._meta.model_name != team_model_name:
        return  # Current prohibition settings only apply to team actors

    if not team_team_allowed and content_type.model == team_model_name:
        raise ValidationError('Assigning team permissions to other teams is not allowed')

    team_parent_model_name = permission_registry.get_parent_model(permission_registry.team_model)._meta.model_name
    if not team_org_allowed and content_type.model == team_parent_model_name:
        raise ValidationError(f'Assigning {team_parent_model_name} permissions to teams is not allowed')

    if not team_org_team_allowed and content_type.model == team_parent_model_name and has_team_perm:
        raise ValidationError(f'Assigning {team_parent_model_name} permissions to teams is not allowed')


def needed_updates_on_assignment(role_definition, actor, object_role, created=False, giving=True):
    """
    If a user or a team is granted a role or has a role revoked,
    then this returns instructions for what needs to be updated
    returns tuple
        (bool: should update team owners, set: object roles to update)
    """
    # we maintain a list of object roles that we need to update evaluations for
    to_update = set()
    if created:
        to_update.add(object_role)

    has_team_perm = role_definition.permissions.filter(codename=permission_registry.team_permission).exists()
    changes_team_owners = False

    # Raise exception if settings prohibits this assignment
    validate_assignment_enabled(actor, object_role.content_type, has_team_perm=has_team_perm)

    # If permissions for team are changed. That tends to affect a lot.
    if actor._meta.model_name != 'user':
        to_update.update(team_ancestor_roles(actor))
        if not giving:
            # this will delete some permission assignments that will be removed from this relationship
            to_update.update(object_role.descendent_roles())
        changes_team_owners = True

    deleted = False
    if (not giving) and (not (object_role.users.exists() or object_role.teams.exists())):
        # time to delete the object role because it is unused
        if object_role in to_update:
            to_update.remove(object_role)
        deleted = True

    # giving or revoking team permissions may not change the parentage
    # but this will still change what downstream roles grant what permissions
    if (has_team_perm and created) or (giving and changes_team_owners):
        to_update.update(object_role.descendent_roles())

    # actions which can change the team parentage structure
    recompute_teams = bool(has_team_perm and (created or deleted or changes_team_owners))

    return (recompute_teams, to_update)


def update_after_assignment(update_teams, to_update):
    "Call this with the output of needed_updates_on_assignment"
    if update_teams:
        compute_team_member_roles()

    compute_object_role_permissions(object_roles=to_update)


def permissions_changed(instance, action, model, pk_set, reverse, **kwargs):
    if action.startswith('pre_'):
        return
    to_recompute = set(ObjectRole.objects.filter(role_definition=instance).prefetch_related('teams__member_roles'))
    if not to_recompute:
        return
    logger.info(f'{instance} permissions {action}, pks={pk_set}')
    if reverse:
        raise RuntimeError('Removal of permssions through reverse relationship not supported')

    if action in ('post_add', 'post_remove'):
        if Permission.objects.filter(codename=permission_registry.team_permission, pk__in=pk_set).exists():
            for object_role in to_recompute.copy():
                to_recompute.update(object_role.descendent_roles())
            compute_team_member_roles()
        # All team member roles that give this permission through this role need to be updated
        for role in to_recompute.copy():
            for team in role.teams.all():
                for team_role in team.member_roles.all():
                    to_recompute.add(team_role)
    elif action == 'post_clear':
        # unfortunately this does not give us a list of permissions to work with
        # this is slow, not ideal, but will at least be correct
        compute_team_member_roles()
        to_recompute = None  # all
    compute_object_role_permissions(object_roles=to_recompute)


m2m_changed.connect(permissions_changed, sender=RoleDefinition.permissions.through)


def set_original_parent(sender, instance, **kwargs):
    '''
    connect to post_init signal
    Used to set the original, or
    pre-save parent id (usually organization), so we can later determine if
    the organization field has changed.
    '''
    parent_field_name = permission_registry.get_parent_fd_name(instance)
    if parent_field_name is None:
        return
    instance.__rbac_original_parent_id = getattr(instance, f'{parent_field_name}_id')


def post_save_update_obj_permissions(instance):
    "Utility method shared by multiple signals"
    to_update = set()
    parent_ct = ContentType.objects.get_for_model(permission_registry.get_parent_model(instance))
    parent_field_name = permission_registry.get_parent_fd_name(instance)

    # Account for organization roles, new and old
    new_parent_id = getattr(instance, f'{parent_field_name}_id')
    if new_parent_id:
        to_update.update(set(ObjectRole.objects.filter(content_type=parent_ct, object_id=new_parent_id)))
    if hasattr(instance, '__rbac_original_parent_id') and instance.__rbac_original_parent_id:
        to_update.update(set(ObjectRole.objects.filter(content_type=parent_ct, object_id=instance.__rbac_original_parent_id)))

    # Account for parent team roles of those organization roles
    ancestors = set(ObjectRole.objects.filter(provides_teams__has_roles__in=to_update))
    to_update.update(ancestors)

    # If the actual object changed (created or modified) was a team, any org role
    # that has member_team needs to be updated, and any parent teams that have that role
    if instance._meta.model_name == permission_registry.team_model._meta.model_name:
        compute_team_member_roles()

    if to_update:
        compute_object_role_permissions(object_roles=to_update)


def recompute_object_role_permissions(instance, created, *args, **kwargs):
    """
    Connect to post_save signal for objects in the permission registry
    If the parent object changes, this rebuilds the cache
    """
    # Exit right away if object does not have any parent objects
    parent_field_name = permission_registry.get_parent_fd_name(instance)
    if parent_field_name is None:
        return

    # If child object is created and parent object has existing ObjectRoles
    # evaluations for the parent object roles need to be added
    if created:
        post_save_update_obj_permissions(instance)
        return

    # The parent object can not have changed if update_fields was given and did not list that field
    update_fields = kwargs.get('update_fields', None)
    if update_fields and not (parent_field_name in update_fields or f'{parent_field_name}_id' in update_fields):
        return

    # Handle the unusual situation where the parent object changes
    current_parent_id = getattr(instance, f'{parent_field_name}_id')
    if hasattr(instance, '__rbac_original_parent_id') and instance.__rbac_original_parent_id != current_parent_id:
        logger.info(f'Object {instance} changed RBAC parent {instance.__rbac_original_parent_id}-->{current_parent_id}')
        post_save_update_obj_permissions(instance)


def team_pre_delete(instance, *args, **kwargs):
    instance.__rbac_stashed_member_roles = list(instance.member_roles.all())


def remove_object_roles(instance, *args, **kwargs):
    """
    Call this when deleting an object to cascade delete its object roles
    Deleting a team can have consequences for the rest of the graph
    """
    if instance._meta.model_name == permission_registry.team_model._meta.model_name:
        indirectly_affected_roles = set()
        indirectly_affected_roles.update(team_ancestor_roles(instance))
        for team_role in instance.__rbac_stashed_member_roles:
            indirectly_affected_roles.update(team_role.descendent_roles())
        compute_team_member_roles()
        compute_object_role_permissions(object_roles=indirectly_affected_roles)

    ct = ContentType.objects.get_for_model(type(instance))
    ObjectRole.objects.filter(content_type=ct, object_id=instance.id).delete()


def post_migration_rbac_setup(*args, **kwargs):
    """
    Return if running django or py.test unit tests.
    Logic is taken from AWX is_testing, it could be cut down on
    """
    if not settings.GATEWAY_ROLE_PRECREATE:
        return

    try:
        RoleDefinition.objects.first()
    except ProgrammingError:
        return  # this happens when migrating backwards, tables do not exist at prior states

    setup_managed_role_definitions(apps, None)
    compute_team_member_roles()
    compute_object_role_permissions()


def connect_rbac_signals(cls):
    if cls._meta.model_name == permission_registry.team_model._meta.model_name:
        pre_delete.connect(team_pre_delete, sender=cls, dispatch_uid='stash-team-roles-before-delete')
    post_save.connect(recompute_object_role_permissions, sender=cls, dispatch_uid='permission-registry-post-save')
    post_delete.connect(remove_object_roles, sender=cls, dispatch_uid='permission-registry-post-delete')
    post_init.connect(set_original_parent, sender=cls, dispatch_uid='permission-registry-save-prior-parent')
