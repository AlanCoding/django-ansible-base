import logging

from django.apps import apps
from django.conf import settings
from django.contrib.contenttypes.models import ContentType

from ansible_base.models.rbac import ObjectRole, RoleDefinition, RoleEvaluation
from ansible_base.rbac.permission_registry import permission_registry
from ansible_base.rbac.prefetch import TypesPrefetch

logger = logging.getLogger('ansible_base.rbac.caching')


'''
This module has callable methods to fill in things marked with COMPUTED DATA in the models
from the user-specifications in other fields.
These need to be called in specific hooks to assure that evaluations remain correct,
logic for triggers are in the triggers module.

NOTE:
This is highly dependent on the model methods ObjectRole.needed_cache_updates and expected_direct_permissions
Those methods are what truly dictate the object-role to object-permission translation
'''


def all_team_parents(team_id, team_team_parents, seen=None):
    """
    Recursive method to take parent teams, and parent teams of parent teams, until we have them all

    team_id: id of the team we want to get the parents of
    team_team_parents: mapping of team id to ids of its parents, this is not modified by this method
    seen: mutable set that will be added to by each call so that we can not recurse infinitely
    """
    parent_team_ids = set()
    if seen is None:
        seen = set()
    for parent_id in team_team_parents.get(team_id, []):
        if parent_id in seen:
            # will be combined in a lower level of the call stack
            # this condition prevents infinite recursion in the event of loops in the graph
            continue
        parent_team_ids.add(parent_id)
        parent_team_ids.update(all_team_parents(parent_id, team_team_parents, seen=parent_team_ids))
    return parent_team_ids


def compute_team_member_roles():
    """
    Fills in the ObjectRole.provides_teams relationship for all teams.
    This relationship is a list of teams that the role grants membership for
    This method is always ran globally.
    """
    # first we need to obtain the direct team membership roles. What is this?
    # If an organization-level role lists "member_team" permission, that confers
    # the team permissions to any user who holes an org role of that type
    # If a team-level role lists "member_team" then that also convers
    # the member permissions to the user
    # these are called "direct" membership roles to a team, and we need them in-memory
    org_type = apps.get_model(settings.ROLE_ORGANIZATION_MODEL)

    # manually prefetch the team and org memberships
    org_team_mapping = {}
    team_fields = ['id']
    if hasattr(permission_registry.team_model, 'organization'):
        team_fields.append('organization_id')
    for team in permission_registry.team_model.objects.only(*team_fields):
        org_team_mapping.setdefault(team.organization_id, [])
        org_team_mapping[team.organization_id].append(team.id)

    # build out the direct member roles for teams
    direct_member_roles = {}
    team_ct = ContentType.objects.get_for_model(permission_registry.team_model)
    org_ct = ContentType.objects.get_for_model(org_type)
    for object_role in ObjectRole.objects.filter(role_definition__permissions__codename=permission_registry.team_permission).iterator():
        if object_role.content_type_id == team_ct.id:
            direct_member_roles.setdefault(object_role.object_id, [])
            direct_member_roles[object_role.object_id].append(object_role.id)
        elif object_role.content_type_id == org_ct.id:
            if object_role.object_id not in org_team_mapping:
                continue  # this means the organization has no team but has member_team as a listed permission
            for team_id in org_team_mapping[object_role.object_id]:
                direct_member_roles.setdefault(team_id, [])
                direct_member_roles[team_id].append(object_role.id)
        else:
            logger.warning(
                f'The role {object_role.role_definition.name} on {object_role.content_type_id}-{object_role.object_id} '
                'grants team membership, which is invalid for that type'
            )

    # Next, things get weird when a team role confers membership to another team
    # the new data we need are the roles that a team is granted, filtered to team permissions
    team_team_parents = {}
    for object_role in ObjectRole.objects.filter(
        role_definition__permissions__codename=permission_registry.team_permission, teams__isnull=False
    ).prefetch_related('teams'):
        for actor_team in object_role.teams.all():
            if object_role.content_type_id == team_ct.id:
                team_team_parents.setdefault(object_role.object_id, [])
                team_team_parents[object_role.object_id].append(actor_team.id)
            elif object_role.content_type_id == org_ct.id:
                # NOTE: this is supporting something we intend to disable when assigning the team to the object role
                logger.warning(
                    f'The role {object_role.role_definition.name} on {object_role.content_object} gives {actor_team} '
                    'an org-team permission, which should not have been allowed'
                )
                if object_role.object_id not in org_team_mapping:
                    continue
                for team_id in org_team_mapping[object_role.object_id]:
                    team_team_parents.setdefault(team_id, [])
                    team_team_parents[team_id].append(actor_team.id)

    # Now we need to crawl the team-team graph to get the full list of roles that grants access to each team
    # for each parent team that grants membership to a team, we need to add the roles that grant
    # membership to that parent team
    all_member_roles = {}
    for team_id, member_roles in direct_member_roles.items():
        all_member_roles[team_id] = set(member_roles)  # will also avoid mutating original data structure later
        for parent_team_id in all_team_parents(team_id, team_team_parents):
            all_member_roles[team_id].update(set(direct_member_roles.get(parent_team_id, [])))

    # Great! we should be done building all_member_roles which tells what roles gives team membership for all teams
    # now at this point we save that data
    for team in permission_registry.team_model.objects.prefetch_related('member_roles'):
        # NOTE: the .set method will not use the prefetched data, thus the messy implementation here
        existing_ids = set(r.id for r in team.member_roles.all())
        expected_ids = set(all_member_roles.get(team.id, []))
        to_add = expected_ids - existing_ids
        to_remove = existing_ids - expected_ids
        if to_add:
            team.member_roles.add(*to_add)
        if to_remove:
            team.member_roles.remove(*to_remove)


def compute_object_role_permissions(object_roles=None, types_prefetch=None):
    """
    Assumes the ObjectRole.provides_teams relationship is correct.
    Makes the RoleEvaluation table correct for all specified object_roles
    """
    to_delete = set()
    to_add = []

    if types_prefetch is None:
        types_prefetch = TypesPrefetch.from_database(RoleDefinition)
    if object_roles is None:
        object_roles = ObjectRole.objects.iterator()

    for object_role in object_roles:
        role_to_delete, role_to_add = object_role.needed_cache_updates(types_prefetch=types_prefetch)

        if role_to_delete:
            logger.debug(f'Removing {len(role_to_delete)} object-permissions from {object_role}')
            to_delete.update(role_to_delete)

        if role_to_add:
            logger.debug(f'Adding {len(role_to_add)} object-permissions to {object_role}')
            to_add.extend(role_to_add)

    if to_add:
        logger.info(f'Adding {len(to_add)} object-permission records')
        RoleEvaluation.objects.bulk_create(to_add)

    if to_delete:
        logger.info(f'Deleting {len(to_delete)} object-permission records')
        RoleEvaluation.objects.filter(id__in=to_delete).delete()
