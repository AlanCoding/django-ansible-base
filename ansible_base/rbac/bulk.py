from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import TYPE_CHECKING, NamedTuple, Union

from django.conf import settings
from django.db import connection, models
from django.db.models import Q

from ansible_base.rbac.models.content_type import DABContentType
from ansible_base.rbac.permission_registry import permission_registry
from ansible_base.rbac.remote import RemoteObject
from ansible_base.rbac.validators import validate_assignment

if TYPE_CHECKING:
    from ansible_base.rbac.models.role import RoleDefinition


class ResolvedAssignment(NamedTuple):
    role_definition: RoleDefinition
    actor: models.Model
    content_type: DABContentType
    object_id: str
    parent_reference: str


ContentObject = Union[models.Model, RemoteObject]
PermissionTriple = tuple['RoleDefinition', models.Model, ContentObject]
ObjectRoleLookup = dict[tuple[int, int, str], 'ObjectRole']


def _resolve_content_object(obj: models.Model | RemoteObject) -> tuple[DABContentType, str, str]:
    """Resolve content_type, object_id, and parent_reference from a content object.

    For RemoteObject: uses its own attributes directly.
    For local Django models: uses _meta (no extra query), empty parent_reference.
    """
    if isinstance(obj, RemoteObject):
        return obj.content_type, str(obj.object_id), str(obj.parent_reference) if obj.parent_reference else ''
    return (
        DABContentType.objects.get_for_model(obj),
        str(obj._meta.pk.get_db_prep_value(obj.pk, connection)),
        '',
    )


def resolve_assignments(
    user_permissions: list[PermissionTriple],
    team_permissions: list[PermissionTriple],
) -> list[ResolvedAssignment]:
    """Validate permissions and build the resolved assignment list."""
    from ansible_base.rbac.validators import validate_team_assignment_enabled

    validated_pairs: set[tuple[int, int]] = set()
    resolved: list[ResolvedAssignment] = []

    for rd, actor, obj in user_permissions:
        obj_ct, object_id, parent_ref = _resolve_content_object(obj)
        key = (rd.pk, obj_ct.id)
        if key not in validated_pairs:
            validate_assignment(rd, actor, obj)
            validated_pairs.add(key)
        resolved.append(ResolvedAssignment(rd, actor, obj_ct, object_id, parent_ref))

    for rd, actor, obj in team_permissions:
        obj_ct, object_id, parent_ref = _resolve_content_object(obj)
        key = (rd.pk, obj_ct.id)
        if key not in validated_pairs:
            validate_assignment(rd, actor, obj)
            has_team_perm = rd.permissions.filter(codename=permission_registry.team_permission).exists()
            has_org_member = rd.permissions.filter(codename='member_organization').exists()
            validate_team_assignment_enabled(obj_ct, has_team_perm=has_team_perm, has_org_member=has_org_member)
            validated_pairs.add(key)
        resolved.append(ResolvedAssignment(rd, actor, obj_ct, object_id, parent_ref))

    return resolved


def ensure_object_roles(resolved: list[ResolvedAssignment]) -> ObjectRoleLookup:
    """Group by (rd_id, ct_id), create missing ObjectRoles, and return lookup."""
    from ansible_base.rbac.models.role import ObjectRole

    groups: dict[tuple[int, int], set[str]] = defaultdict(set)
    parent_refs: dict[str, str] = {}
    for ra in resolved:
        groups[(ra.role_definition.pk, ra.content_type.id)].add(ra.object_id)
        if ra.parent_reference:
            parent_refs[ra.object_id] = ra.parent_reference

    lookup: ObjectRoleLookup = {}
    for (rd_id, ct_id), object_ids in groups.items():
        for obj_role in ObjectRole.objects.filter(role_definition_id=rd_id, content_type_id=ct_id, object_id__in=object_ids):
            lookup[(rd_id, ct_id, obj_role.object_id)] = obj_role
        missing = [oid for oid in object_ids if (rd_id, ct_id, oid) not in lookup]
        if missing:
            ObjectRole.objects.bulk_create(
                [ObjectRole(role_definition_id=rd_id, content_type_id=ct_id, object_id=oid, parent_reference=parent_refs.get(oid, '')) for oid in missing],
                ignore_conflicts=True,
            )
            for obj_role in ObjectRole.objects.filter(role_definition_id=rd_id, content_type_id=ct_id, object_id__in=missing):
                lookup[(rd_id, ct_id, obj_role.object_id)] = obj_role

    return lookup


def _audit_log_created(db_assignments, existing_pks):
    """Emit audit logs for newly-created assignments (not idempotent re-assignments)."""
    if not db_assignments or 'ansible_base.activitystream' not in settings.INSTALLED_APPS:
        return

    from ansible_base.activitystream.signals import _store_activitystream_entry

    for assignment in db_assignments:
        if assignment.pk not in existing_pks:
            _store_activitystream_entry(None, assignment, 'create')


def create_assignments(
    resolved: list[ResolvedAssignment],
    lookup: ObjectRoleLookup,
    num_user_perms: int,
) -> list:
    """Bulk-create user and team assignment objects, return all resulting assignments."""
    from ansible_base.lib.utils.models import current_user_or_system_user
    from ansible_base.rbac.models.role import RoleTeamAssignment, RoleUserAssignment

    created_by = current_user_or_system_user()
    all_assignments = []

    user_assignments = []
    for ra in resolved[:num_user_perms]:
        obj_role = lookup[(ra.role_definition.pk, ra.content_type.id, ra.object_id)]
        user_assignments.append(
            RoleUserAssignment(
                user=ra.actor,
                object_role=obj_role,
                role_definition=ra.role_definition,
                content_type=ra.content_type,
                object_id=ra.object_id,
                created_by=created_by,
            )
        )
    if user_assignments:
        existing_user_pks = set(
            RoleUserAssignment.objects.filter(
                object_role__in=[a.object_role for a in user_assignments],
                user__in=[a.user for a in user_assignments],
            ).values_list('pk', flat=True)
        )
        RoleUserAssignment.objects.bulk_create(user_assignments, ignore_conflicts=True)
        db_users = list(
            RoleUserAssignment.objects.filter(
                object_role__in=[a.object_role for a in user_assignments],
                user__in=[a.user for a in user_assignments],
            )
        )
        all_assignments.extend(db_users)
        _audit_log_created(db_users, existing_user_pks)

    team_assignments = []
    for ra in resolved[num_user_perms:]:
        obj_role = lookup[(ra.role_definition.pk, ra.content_type.id, ra.object_id)]
        team_assignments.append(
            RoleTeamAssignment(
                team=ra.actor,
                object_role=obj_role,
                role_definition=ra.role_definition,
                content_type=ra.content_type,
                object_id=ra.object_id,
                created_by=created_by,
            )
        )
    if team_assignments:
        existing_team_pks = set(
            RoleTeamAssignment.objects.filter(
                object_role__in=[a.object_role for a in team_assignments],
                team__in=[a.team for a in team_assignments],
            ).values_list('pk', flat=True)
        )
        RoleTeamAssignment.objects.bulk_create(team_assignments, ignore_conflicts=True)
        db_teams = list(
            RoleTeamAssignment.objects.filter(
                object_role__in=[a.object_role for a in team_assignments],
                team__in=[a.team for a in team_assignments],
            )
        )
        all_assignments.extend(db_teams)
        _audit_log_created(db_teams, existing_team_pks)

    return all_assignments


def collect_recompute_team_ids(lookup: ObjectRoleLookup) -> set[int]:
    """Identify team IDs that need member-role recomputation."""
    from ansible_base.rbac.models.role import RoleDefinition
    from ansible_base.rbac.triggers import _team_ids_from_role_target

    rd_has_team_perm: dict[int, bool] = {}
    for rd_id, _ct_id, _oid in lookup:
        if rd_id not in rd_has_team_perm:
            rd_has_team_perm[rd_id] = RoleDefinition.objects.filter(pk=rd_id, permissions__codename=permission_registry.team_permission).exists()
    team_rd_ids = {rd_id for rd_id, has_perm in rd_has_team_perm.items() if has_perm}

    recompute_team_ids: set[int] = set()
    for (rd_id, _ct_id, _oid), obj_role in lookup.items():
        if rd_id in team_rd_ids:
            recompute_team_ids.update(_team_ids_from_role_target(obj_role))
    return recompute_team_ids


def recompute_after_give(
    lookup: ObjectRoleLookup,
    resolved: list[ResolvedAssignment],
    num_user_perms: int,
    has_team_perms: bool,
) -> None:
    """Run recomputation pass after bulk permission assignment."""
    from ansible_base.rbac.caching import compute_object_role_permissions, compute_team_member_roles
    from ansible_base.rbac.models.role import ObjectRole
    from ansible_base.rbac.triggers import team_ancestor_roles

    recompute_team_ids = collect_recompute_team_ids(lookup)
    object_roles_to_update: set[ObjectRole] = set(lookup.values())

    if has_team_perms:
        unique_teams = {ra.actor for ra in resolved[num_user_perms:]}
        for team in unique_teams:
            object_roles_to_update.update(team_ancestor_roles(team))
        prefetched = ObjectRole.objects.filter(pk__in=[obj_role.pk for obj_role in object_roles_to_update]).prefetch_related('provides_teams__has_roles')
        for obj_role in prefetched:
            object_roles_to_update.update(obj_role.descendent_roles())

    if recompute_team_ids:
        compute_team_member_roles(team_ids=recompute_team_ids)
    if object_roles_to_update:
        prefetched_object_roles = ObjectRole.objects.filter(pk__in=[obj_role.pk for obj_role in object_roles_to_update]).prefetch_related(
            'provides_teams__has_roles'
        )
        compute_object_role_permissions(object_roles=prefetched_object_roles)


def delete_assignments(
    resolved: list[ResolvedAssignment],
    lookup: ObjectRoleLookup,
    num_user_perms: int,
) -> None:
    """Delete assignments using pair-specific Q objects to avoid cross-product deletion."""
    from ansible_base.rbac.models.role import RoleTeamAssignment, RoleUserAssignment

    for assignments, model, actor_field in [
        (resolved[:num_user_perms], RoleUserAssignment, 'user_id'),
        (resolved[num_user_perms:], RoleTeamAssignment, 'team_id'),
    ]:
        if not assignments:
            continue
        q = Q()
        for ra in assignments:
            obj_role = lookup.get((ra.role_definition.pk, ra.content_type.id, ra.object_id))
            if obj_role is not None:
                q |= Q(object_role_id=obj_role.pk, **{actor_field: ra.actor.pk})
        if q:
            model.objects.filter(q).delete()


def find_object_roles(
    permissions_list: list[PermissionTriple],
) -> tuple[ObjectRoleLookup, list[ResolvedAssignment]]:
    """Build ObjectRole lookup from a list of (rd, actor, obj) triples.

    Returns (lookup, resolved) where resolved includes content_type
    and object_id for each entry.
    """
    from ansible_base.rbac.models.role import ObjectRole

    groups: dict[tuple[int, int], set[str]] = defaultdict(set)
    resolved: list[ResolvedAssignment] = []
    for rd, actor, obj in permissions_list:
        obj_ct, object_id, parent_ref = _resolve_content_object(obj)
        groups[(rd.pk, obj_ct.id)].add(object_id)
        resolved.append(ResolvedAssignment(rd, actor, obj_ct, object_id, parent_ref))

    lookup: ObjectRoleLookup = {}
    for (rd_id, ct_id), object_ids in groups.items():
        for obj_role in ObjectRole.objects.filter(role_definition_id=rd_id, content_type_id=ct_id, object_id__in=object_ids):
            lookup[(rd_id, ct_id, obj_role.object_id)] = obj_role

    return lookup, resolved


def bulk_give_permissions(
    user_permissions: Iterable[PermissionTriple] = (),
    team_permissions: Iterable[PermissionTriple] = (),
) -> list:
    """Bulk-assign multiple roles to multiple users/teams on multiple objects.

    user_permissions: iterable of (role_definition, user, content_object) triples
    team_permissions: iterable of (role_definition, team, content_object) triples

    Returns the list of all resulting assignment objects (both new and
    pre-existing for idempotent calls).

    This is the bulk replacement for give_permission. It validates once per
    unique (role_definition, content_type) pair, bulk-creates ObjectRoles and
    assignments, then runs a single recomputation pass.
    """
    user_permissions = list(user_permissions)
    team_permissions = list(team_permissions)
    if not user_permissions and not team_permissions:
        return []

    resolved = resolve_assignments(user_permissions, team_permissions)
    lookup = ensure_object_roles(resolved)
    assignments = create_assignments(resolved, lookup, len(user_permissions))
    recompute_after_give(lookup, resolved, len(user_permissions), bool(team_permissions))
    return assignments


def bulk_remove_permissions(
    user_permissions: Iterable[PermissionTriple] = (),
    team_permissions: Iterable[PermissionTriple] = (),
) -> None:
    """Bulk-remove multiple role assignments.

    user_permissions: iterable of (role_definition, user, content_object) triples
    team_permissions: iterable of (role_definition, team, content_object) triples

    This is the bulk replacement for remove_permission. Deletes assignments,
    cleans up orphaned ObjectRoles, and runs a single recomputation pass.
    """
    from ansible_base.rbac.caching import compute_object_role_permissions, compute_team_member_roles
    from ansible_base.rbac.models.role import ObjectRole

    user_permissions = list(user_permissions)
    team_permissions = list(team_permissions)
    if not user_permissions and not team_permissions:
        return

    lookup, resolved = find_object_roles(user_permissions + team_permissions)
    if not lookup:
        return

    all_object_role_ids = {obj_role.pk for obj_role in lookup.values()}
    delete_assignments(resolved, lookup, len(user_permissions))

    orphaned = ObjectRole.objects.filter(id__in=all_object_role_ids, users__isnull=True, teams__isnull=True)
    orphaned_ids = set(orphaned.values_list('id', flat=True))
    surviving = {obj_role for obj_role in lookup.values() if obj_role.pk not in orphaned_ids}

    recompute_team_ids = collect_recompute_team_ids(lookup)

    if team_permissions:
        from ansible_base.rbac.triggers import team_ancestor_roles

        for obj_role in lookup.values():
            surviving.update(obj_role.descendent_roles())
        for _rd, team, _obj in team_permissions:
            surviving.update(team_ancestor_roles(team))

    orphaned.delete()

    if recompute_team_ids:
        compute_team_member_roles(team_ids=recompute_team_ids)
    if surviving:
        compute_object_role_permissions(object_roles=surviving)
