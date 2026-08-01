from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable, Sequence
from typing import NamedTuple, Union

from django.conf import settings
from django.db import connection, models
from django.db.models import Q
from django.db.models.signals import post_save

from ansible_base.lib.utils.models import current_user_or_system_user
from ansible_base.rbac.caching import compute_object_role_permissions, compute_team_member_roles
from ansible_base.rbac.models.content_type import DABContentType
from ansible_base.rbac.models.role import AssignmentBase, ObjectRole, RoleDefinition, RoleTeamAssignment, RoleUserAssignment
from ansible_base.rbac.permission_registry import permission_registry
from ansible_base.rbac.remote import RemoteObject
from ansible_base.rbac.triggers import _team_ids_from_role_target, team_ancestor_roles
from ansible_base.rbac.validators import validate_assignment, validate_team_assignment_enabled

logger = logging.getLogger(__name__)


class ResolvedAssignment(NamedTuple):
    role_definition: RoleDefinition
    actor: models.Model
    content_type: DABContentType
    object_id: str
    parent_reference: str


ContentObject = Union[models.Model, RemoteObject]
PermissionTriple = tuple[RoleDefinition, models.Model, ContentObject]
ObjectRoleLookup = dict[tuple[int, str], ObjectRole]


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


def _resolve_triples(triples: Iterable[PermissionTriple]) -> list[ResolvedAssignment]:
    """Convert permission triples to ResolvedAssignments (no validation, no DB queries beyond content type lookup)."""
    return [ResolvedAssignment(rd, actor, *_resolve_content_object(obj)) for rd, actor, obj in triples]


def resolve_assignments(
    user_permissions: Sequence[PermissionTriple],
    team_permissions: Sequence[PermissionTriple],
) -> tuple[list[ResolvedAssignment], list[ResolvedAssignment]]:
    """Validate permissions and build the resolved assignment lists."""
    validated_pairs: set[tuple[int, int]] = set()

    user_resolved: list[ResolvedAssignment] = []
    for rd, actor, obj in user_permissions:
        obj_ct, object_id, parent_ref = _resolve_content_object(obj)
        key = (rd.pk, obj_ct.id)
        if key not in validated_pairs:
            validate_assignment(rd, actor, obj)
            validated_pairs.add(key)
        user_resolved.append(ResolvedAssignment(rd, actor, obj_ct, object_id, parent_ref))

    team_resolved: list[ResolvedAssignment] = []
    for rd, actor, obj in team_permissions:
        obj_ct, object_id, parent_ref = _resolve_content_object(obj)
        key = (rd.pk, obj_ct.id)
        if key not in validated_pairs:
            validate_assignment(rd, actor, obj)
            has_team_perm = rd.permissions.filter(codename=permission_registry.team_permission).exists()
            has_org_member = rd.permissions.filter(codename='member_organization').exists()
            validate_team_assignment_enabled(obj_ct, has_team_perm=has_team_perm, has_org_member=has_org_member)
            validated_pairs.add(key)
        team_resolved.append(ResolvedAssignment(rd, actor, obj_ct, object_id, parent_ref))

    return user_resolved, team_resolved


def _lookup_object_roles(resolved: list[ResolvedAssignment]) -> ObjectRoleLookup:
    """Look up existing ObjectRoles for resolved assignments."""
    object_ids_by_rd: dict[int, tuple[int, set[str]]] = {}
    for ra in resolved:
        rd_id = ra.role_definition.pk
        if rd_id not in object_ids_by_rd:
            object_ids_by_rd[rd_id] = (ra.content_type.id, set())
        object_ids_by_rd[rd_id][1].add(ra.object_id)

    lookup: ObjectRoleLookup = {}
    for rd_id, (ct_id, object_ids) in object_ids_by_rd.items():
        for obj_role in ObjectRole.objects.filter(role_definition_id=rd_id, content_type_id=ct_id, object_id__in=object_ids):
            lookup[(rd_id, obj_role.object_id)] = obj_role

    return lookup


def ensure_object_roles(requested_assignments: list[ResolvedAssignment]) -> ObjectRoleLookup:
    """Look up existing ObjectRoles, create any that are missing, and return the full lookup."""
    object_ids_by_rd: dict[int, tuple[int, set[str]]] = {}
    parent_refs: dict[str, str] = {}
    for ra in requested_assignments:
        rd_id = ra.role_definition.pk
        if rd_id not in object_ids_by_rd:
            object_ids_by_rd[rd_id] = (ra.content_type.id, set())
        object_ids_by_rd[rd_id][1].add(ra.object_id)
        if ra.parent_reference:
            parent_refs[ra.object_id] = ra.parent_reference

    lookup: ObjectRoleLookup = {}
    for rd_id, (ct_id, object_ids) in object_ids_by_rd.items():
        for obj_role in ObjectRole.objects.filter(role_definition_id=rd_id, content_type_id=ct_id, object_id__in=object_ids):
            lookup[(rd_id, obj_role.object_id)] = obj_role
        missing = [oid for oid in object_ids if (rd_id, oid) not in lookup]
        if missing:
            ObjectRole.objects.bulk_create(
                [ObjectRole(role_definition_id=rd_id, content_type_id=ct_id, object_id=oid, parent_reference=parent_refs.get(oid, '')) for oid in missing],
                ignore_conflicts=True,
            )
            # Re-fetch to get PKs — bulk_create(ignore_conflicts=True) doesn't populate them.
            # unique_together on (role_definition, content_type, object_id) guarantees one row per oid.
            for obj_role in ObjectRole.objects.filter(role_definition_id=rd_id, content_type_id=ct_id, object_id__in=missing):
                lookup[(rd_id, obj_role.object_id)] = obj_role

    return lookup


def _audit_log_created(db_assignments: list[AssignmentBase], existing_pks: set[int]) -> None:
    """Emit audit logs for newly-created assignments (not idempotent re-assignments)."""
    if not db_assignments or 'ansible_base.activitystream' not in settings.INSTALLED_APPS:
        return

    from ansible_base.activitystream.signals import _store_activitystream_entry

    for assignment in db_assignments:
        if assignment.pk not in existing_pks:
            _store_activitystream_entry(None, assignment, 'create')


def _pair_filter(assignments: list[AssignmentBase], actor_field: str) -> Q:
    """Build a Q filter matching exact (actor, object_role) pairs — no cross-product."""
    q = Q()
    for a in assignments:
        q |= Q(**{actor_field: getattr(a, actor_field), 'object_role': a.object_role})
    return q


def _fire_post_save(db_assignments: list[AssignmentBase], existing_pks: set[int]) -> None:
    """Fire post_save signals for newly-created assignments (skipped by bulk_create)."""
    for assignment in db_assignments:
        if assignment.pk not in existing_pks:
            post_save.send(sender=type(assignment), instance=assignment, created=True, raw=False, using='default', update_fields=None)


def create_assignments(
    user_resolved: list[ResolvedAssignment],
    team_resolved: list[ResolvedAssignment],
    lookup: ObjectRoleLookup,
    fire_signals_on_create: bool = True,
) -> list[AssignmentBase]:
    """Bulk-create user and team assignment objects, return all resulting assignments."""
    created_by = current_user_or_system_user()
    all_assignments = []

    user_assignments = []
    for ra in user_resolved:
        obj_role = lookup[(ra.role_definition.pk, ra.object_id)]
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
        pair_q = _pair_filter(user_assignments, 'user')
        existing_user_pks = set(RoleUserAssignment.objects.filter(pair_q).values_list('pk', flat=True))
        RoleUserAssignment.objects.bulk_create(user_assignments, ignore_conflicts=True)
        db_users = list(RoleUserAssignment.objects.filter(pair_q))
        all_assignments.extend(db_users)
        if fire_signals_on_create:
            _fire_post_save(db_users, existing_user_pks)
        else:
            _audit_log_created(db_users, existing_user_pks)

    team_assignments = []
    for ra in team_resolved:
        obj_role = lookup[(ra.role_definition.pk, ra.object_id)]
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
        pair_q = _pair_filter(team_assignments, 'team')
        existing_team_pks = set(RoleTeamAssignment.objects.filter(pair_q).values_list('pk', flat=True))
        RoleTeamAssignment.objects.bulk_create(team_assignments, ignore_conflicts=True)
        db_teams = list(RoleTeamAssignment.objects.filter(pair_q))
        all_assignments.extend(db_teams)
        if fire_signals_on_create:
            _fire_post_save(db_teams, existing_team_pks)
        else:
            _audit_log_created(db_teams, existing_team_pks)

    return all_assignments


def collect_recompute_team_ids(lookup: ObjectRoleLookup) -> set[int]:
    """Identify team IDs that need member-role recomputation."""
    rd_has_team_perm: dict[int, bool] = {}
    for rd_id, _oid in lookup:
        if rd_id not in rd_has_team_perm:
            rd_has_team_perm[rd_id] = RoleDefinition.objects.filter(pk=rd_id, permissions__codename=permission_registry.team_permission).exists()
    team_rd_ids = {rd_id for rd_id, has_perm in rd_has_team_perm.items() if has_perm}

    recompute_team_ids: set[int] = set()
    for (rd_id, _oid), obj_role in lookup.items():
        if rd_id in team_rd_ids:
            recompute_team_ids.update(_team_ids_from_role_target(obj_role))
    return recompute_team_ids


def recompute_after_give(
    lookup: ObjectRoleLookup,
    assignments: list[AssignmentBase],
) -> None:
    """Run recomputation pass after bulk permission assignment."""
    recompute_team_ids = collect_recompute_team_ids(lookup)
    object_roles_to_update: set[ObjectRole] = set(lookup.values())

    unique_teams = {a.team for a in assignments if isinstance(a, RoleTeamAssignment)}
    if unique_teams:
        for team in unique_teams:
            object_roles_to_update.update(team_ancestor_roles(team))
        expanded_roles = ObjectRole.objects.filter(pk__in=[obj_role.pk for obj_role in object_roles_to_update]).prefetch_related('provides_teams__has_roles')
        for obj_role in expanded_roles:
            object_roles_to_update.update(obj_role.descendent_roles())

    if recompute_team_ids:
        compute_team_member_roles(team_ids=recompute_team_ids)
    if object_roles_to_update:
        roles_to_recompute = ObjectRole.objects.filter(pk__in=[obj_role.pk for obj_role in object_roles_to_update]).prefetch_related(
            'provides_teams__has_roles'
        )
        compute_object_role_permissions(object_roles=roles_to_recompute)


def delete_assignments(
    user_resolved: list[ResolvedAssignment],
    team_resolved: list[ResolvedAssignment],
    lookup: ObjectRoleLookup,
) -> None:
    """Delete assignments using pair-specific Q objects to avoid cross-product deletion."""
    for batch, model, actor_field in [
        (user_resolved, RoleUserAssignment, 'user_id'),
        (team_resolved, RoleTeamAssignment, 'team_id'),
    ]:
        if not batch:
            continue
        q = Q()
        for ra in batch:
            obj_role = lookup.get((ra.role_definition.pk, ra.object_id))
            if obj_role is not None:
                q |= Q(object_role_id=obj_role.pk, **{actor_field: ra.actor.pk})
        if q:
            model.objects.filter(q).delete()


def bulk_give_permissions(
    user_permissions: Sequence[PermissionTriple] = (),
    team_permissions: Sequence[PermissionTriple] = (),
    fire_signals_on_create: bool = True,
) -> list[AssignmentBase]:
    """Bulk-assign multiple roles to multiple users/teams on multiple objects.

    user_permissions: sequence of (role_definition, user, content_object) triples
    team_permissions: sequence of (role_definition, team, content_object) triples
    fire_signals_on_create: if True (default), fire post_save for each new
        assignment. Set to False when the caller handles downstream sync
        (e.g. JWT claims).

    Returns all resulting assignment objects (both new and pre-existing).
    """
    if not user_permissions and not team_permissions:
        return []

    user_resolved, team_resolved = resolve_assignments(user_permissions, team_permissions)
    lookup = ensure_object_roles(user_resolved + team_resolved)
    assignments = create_assignments(user_resolved, team_resolved, lookup, fire_signals_on_create=fire_signals_on_create)
    recompute_after_give(lookup, assignments)
    return assignments


def bulk_remove_permissions(
    user_permissions: Sequence[PermissionTriple] = (),
    team_permissions: Sequence[PermissionTriple] = (),
) -> None:
    """Bulk-remove multiple role assignments.

    user_permissions: sequence of (role_definition, user, content_object) triples
    team_permissions: sequence of (role_definition, team, content_object) triples

    This is the bulk replacement for remove_permission. Deletes assignments,
    cleans up orphaned ObjectRoles, and runs a single recomputation pass.
    """
    if not user_permissions and not team_permissions:
        return

    user_resolved = _resolve_triples(user_permissions)
    team_resolved = _resolve_triples(team_permissions)
    lookup = _lookup_object_roles(user_resolved + team_resolved)
    if not lookup:
        return

    delete_assignments(user_resolved, team_resolved, lookup)

    recompute_team_ids = collect_recompute_team_ids(lookup)
    object_roles_to_update: set[ObjectRole] = set(lookup.values())

    if team_permissions:
        for obj_role in list(object_roles_to_update):
            object_roles_to_update.update(obj_role.descendent_roles())
        for _rd, team, _obj in team_permissions:
            object_roles_to_update.update(team_ancestor_roles(team))

    if recompute_team_ids:
        compute_team_member_roles(team_ids=recompute_team_ids)
    if object_roles_to_update:
        # Re-fetch from DB: signal handlers during delete_assignments may have
        # deleted ObjectRoles, leaving stale in-memory references.
        surviving_object_roles = ObjectRole.objects.filter(pk__in=[o.pk for o in object_roles_to_update])
        compute_object_role_permissions(object_roles=surviving_object_roles)

    deleted_count, _ = ObjectRole.objects.filter(id__in={obj_role.pk for obj_role in lookup.values()}, users__isnull=True, teams__isnull=True).delete()
    if deleted_count:
        logger.debug('Cleaned up %d orphaned ObjectRole(s)', deleted_count)
