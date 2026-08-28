from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from typing import NamedTuple, Union

from django.conf import settings
from django.db import connection, models
from django.db.models import Q
from django.db.models.signals import post_save  # TEMPORARY: see _fire_post_save / AAP-90162 merge-order note

from ansible_base.lib.utils.models import current_user_or_system_user
from ansible_base.rbac.caching import (
    bulk_ancestor_roles,
    compute_team_member_roles,
    defer_rbac_state,
    recompute_role_evaluations,
    team_ids_from_role_target,
)
from ansible_base.rbac.models.content_type import DABContentType
from ansible_base.rbac.models.role import AssignmentBase, ObjectRole, RoleDefinition, RoleTeamAssignment, RoleUserAssignment
from ansible_base.rbac.permission_registry import permission_registry
from ansible_base.rbac.remote import RemoteObject
from ansible_base.rbac.triggers import dab_rbac_assignments_created, dab_rbac_assignments_pre_delete
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


def _resolve_triples(
    triples: Iterable[PermissionTriple],
    collect_content_objects: bool = False,
) -> tuple[list[ResolvedAssignment], dict[tuple[int, str], ContentObject] | None]:
    """Convert permission triples to ResolvedAssignments (no validation, no DB queries beyond content type lookup).

    Args:
        collect_content_objects: If True, also build a dict mapping (content_type_id, object_id)
            to content objects for signal use.

    Returns:
        (resolved_assignments, content_objects_dict or None)
    """
    resolved = []
    content_objects: dict[tuple[int, str], ContentObject] | None = {} if collect_content_objects else None

    for rd, actor, obj in triples:
        ct, object_id, parent_ref = _resolve_content_object(obj)
        resolved.append(ResolvedAssignment(rd, actor, ct, object_id, parent_ref))
        if content_objects is not None:
            content_objects[(ct.id, object_id)] = obj

    return resolved, content_objects


def _resolve_assignments(
    user_permissions: Sequence[PermissionTriple],
    team_permissions: Sequence[PermissionTriple],
    collect_content_objects: bool = False,
) -> tuple[list[ResolvedAssignment], list[ResolvedAssignment], dict[tuple[int, str], ContentObject] | None]:
    """Validate permissions and build the resolved assignment lists.

    Args:
        collect_content_objects: If True, also build a dict mapping (content_type_id, object_id)
            to content objects for signal use. This avoids double-looping and double-resolving.

    Returns:
        (user_resolved, team_resolved, content_objects_dict or None)
    """
    validated_pairs: set[tuple[int, int]] = set()
    content_objects: dict[tuple[int, str], ContentObject] | None = {} if collect_content_objects else None

    user_resolved: list[ResolvedAssignment] = []
    for rd, actor, obj in user_permissions:
        obj_ct, object_id, parent_ref = _resolve_content_object(obj)
        key = (rd.pk, obj_ct.id)
        if key not in validated_pairs:
            validate_assignment(rd, actor, obj)
            validated_pairs.add(key)
        user_resolved.append(ResolvedAssignment(rd, actor, obj_ct, object_id, parent_ref))
        if content_objects is not None:
            content_objects[(obj_ct.id, object_id)] = obj

    team_validated_pairs: set[tuple[int, int]] = set()
    team_resolved: list[ResolvedAssignment] = []
    for rd, actor, obj in team_permissions:
        obj_ct, object_id, parent_ref = _resolve_content_object(obj)
        key = (rd.pk, obj_ct.id)
        if key not in validated_pairs:
            validate_assignment(rd, actor, obj)
            validated_pairs.add(key)
        if key not in team_validated_pairs:
            has_team_perm = rd.permissions.filter(codename=permission_registry.team_permission).exists()
            has_org_member = rd.permissions.filter(codename='member_organization').exists()
            validate_team_assignment_enabled(obj_ct, has_team_perm=has_team_perm, has_org_member=has_org_member)
            team_validated_pairs.add(key)
        team_resolved.append(ResolvedAssignment(rd, actor, obj_ct, object_id, parent_ref))
        if content_objects is not None:
            content_objects[(obj_ct.id, object_id)] = obj

    return user_resolved, team_resolved, content_objects


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


def _ensure_object_roles(requested_assignments: list[ResolvedAssignment]) -> ObjectRoleLookup:
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


def _audit_log_created(created_assignments: list[AssignmentBase]) -> None:
    """Emit audit logs for newly-created assignments (not idempotent re-assignments).

    This is the END-STATE audit path for bulk-created assignments: DAB audits its own rows
    directly without re-firing post_save. It is intentionally retained but NOT called during
    the AAP-90162 merge window -- _create_assignments calls _fire_post_save instead so
    not-yet-migrated consumers keep working. The final cleanup PR swaps the call back here
    and deletes _fire_post_save. See _fire_post_save for the full rationale.
    """
    if not created_assignments or 'ansible_base.activitystream' not in settings.INSTALLED_APPS:
        return

    from ansible_base.activitystream.signals import _store_activitystream_entry

    for assignment in created_assignments:
        _store_activitystream_entry(None, assignment, 'create')


def _insert_new(assignments: list[AssignmentBase], actor_id_field: str, model: type[AssignmentBase]) -> list[AssignmentBase]:
    """Bulk-insert assignments and return only the newly-created rows.

    New rows are detected by PK range -- id greater than the max seen before the insert --
    rather than a per-pair filter, so the query is constant-size regardless of batch shape
    (skinny or fat) and rides the existing PK index. Results are narrowed to the batch's
    exact (actor, object_role) pairs so a row a concurrent caller commits in the id gap
    doesn't leak in. (A genuine same-pair concurrent insert can still be double-counted as
    created -- the same race window as before this change.)

    Pre-existing pairs are deliberately NOT returned. bulk_create(ignore_conflicts=True)
    reports neither which rows it skipped nor their PKs, and fetching them back is precisely
    the query that does not scale (an OR-of-pairs SQLite rejects past ~1000 terms). Callers
    needing a pre-existing row must fetch it themselves -- see RoleDefinition.give_permission.

    Callers guard against the empty case (see _create_assignments), so ``assignments`` is
    always non-empty here.
    """
    batch_pairs = {(getattr(a, actor_id_field), a.object_role_id) for a in assignments}
    max_before = model.objects.aggregate(_m=models.Max('id'))['_m'] or 0
    model.objects.bulk_create(assignments, ignore_conflicts=True)

    return [row for row in model.objects.filter(id__gt=max_before) if (getattr(row, actor_id_field), row.object_role_id) in batch_pairs]


def _fire_post_save(created_assignments: list[AssignmentBase]) -> None:
    """Re-fire post_save (created=True) for rows bulk_create inserted without signalling.

    ~~~ TEMPORARY -- REMOVE WITH AAP-90162 CONSUMER MIGRATION ~~~

    This exists ONLY to keep the merge order clean. The end state (see _audit_log_created)
    is that DAB does NOT re-fire post_save for bulk-created assignments: DAB audits its own
    rows directly, and external consumers (AWX, Hub) move to the bulk signals
    (dab_rbac_assignments_created / dab_rbac_assignments_pre_delete).

    But until the AWX (AAP-90164) and Hub (AAP-90165) patches land, those consumers still
    have per-row post_save receivers on RoleUserAssignment / RoleTeamAssignment. If DAB
    stopped firing post_save before they migrate, their old-RBAC mirroring and activity
    stream would silently break (their downstream test suites fail). So we keep firing it.

    This knowingly re-introduces the per-row-signal performance cost in AWX for the interim.
    That regression is self-correcting: once the AWX patch removes its post_save receivers
    and connects to the bulk signals, this call does nothing for AWX, and the FINAL DAB
    cleanup PR deletes _fire_post_save (and this import) and switches back to
    _audit_log_created. DO NOT build anything new on top of this re-fire.
    """
    for assignment in created_assignments:
        post_save.send(sender=type(assignment), instance=assignment, created=True, raw=False, using='default', update_fields=None)


def _create_assignments(
    user_resolved: list[ResolvedAssignment],
    team_resolved: list[ResolvedAssignment],
    lookup: ObjectRoleLookup,
) -> list[AssignmentBase]:
    """Bulk-create user and team assignment objects; return only the newly-created rows.

    Pre-existing (idempotent) pairs are deliberately omitted -- see _insert_new for why.

    Newly-created rows drive audit + downstream mirroring. The END STATE is a direct
    _audit_log_created() call (DAB audits itself; consumers use the bulk signals). During
    the AAP-90162 merge window we instead re-fire post_save via _fire_post_save() so
    not-yet-migrated consumers (AWX, Hub) keep working -- see that function's docstring.
    We must call ONE of the two, never both: post_save re-drives DAB's own
    activitystream_create receiver, so pairing it with _audit_log_created would double-audit.
    """
    created_by = current_user_or_system_user()
    created_assignments: list[AssignmentBase] = []

    user_assignments = [
        RoleUserAssignment(
            user=ra.actor,
            object_role=lookup[(ra.role_definition.pk, ra.object_id)],
            role_definition=ra.role_definition,
            content_type=ra.content_type,
            object_id=ra.object_id,
            created_by=created_by,
        )
        for ra in user_resolved
    ]
    if user_assignments:
        created_user_assignments = _insert_new(user_assignments, 'user_id', RoleUserAssignment)
        created_assignments.extend(created_user_assignments)
        # TEMPORARY (AAP-90162 merge order): _fire_post_save instead of _audit_log_created.
        _fire_post_save(created_user_assignments)

    team_assignments = [
        RoleTeamAssignment(
            team=ra.actor,
            object_role=lookup[(ra.role_definition.pk, ra.object_id)],
            role_definition=ra.role_definition,
            content_type=ra.content_type,
            object_id=ra.object_id,
            created_by=created_by,
        )
        for ra in team_resolved
    ]
    if team_assignments:
        created_team_assignments = _insert_new(team_assignments, 'team_id', RoleTeamAssignment)
        created_assignments.extend(created_team_assignments)
        # TEMPORARY (AAP-90162 merge order): _fire_post_save instead of _audit_log_created.
        _fire_post_save(created_team_assignments)

    return created_assignments


def _collect_recompute_team_ids(object_roles: Iterable[ObjectRole]) -> set[int]:
    """Identify team IDs that need member-role recomputation."""
    rd_has_team_perm: dict[int, bool] = {}
    recompute_team_ids: set[int] = set()
    for obj_role in object_roles:
        rd_id = obj_role.role_definition_id
        if rd_id not in rd_has_team_perm:
            rd_has_team_perm[rd_id] = RoleDefinition.objects.filter(pk=rd_id, permissions__codename=permission_registry.team_permission).exists()
        if rd_has_team_perm[rd_id]:
            recompute_team_ids.update(team_ids_from_role_target(obj_role))
    return recompute_team_ids


def _check_defer_guard() -> None:
    if defer_rbac_state.active and defer_rbac_state.has_deferred_data:
        raise RuntimeError(
            "Permission assignment/removal cannot be called inside defer_rbac_computations "
            "after resources have been created or deleted. RoleEvaluation data is stale."
        )


def _recompute_after_give(
    lookup: ObjectRoleLookup,
    assignments: list[AssignmentBase],
) -> None:
    """Run recomputation pass after bulk permission assignment."""
    _check_defer_guard()
    recompute_team_ids = _collect_recompute_team_ids(lookup.values())
    object_roles_to_update: set[ObjectRole] = set(lookup.values())

    unique_teams = {a.team for a in assignments if isinstance(a, RoleTeamAssignment)}
    if unique_teams:
        direct_roles = ObjectRole.objects.filter(pk__in=[obj_role.pk for obj_role in object_roles_to_update]).prefetch_related('provides_teams__has_roles')
        for obj_role in direct_roles:
            object_roles_to_update.update(obj_role.descendent_roles())
        object_roles_to_update.update(bulk_ancestor_roles({team.pk for team in unique_teams}))

    if recompute_team_ids:
        compute_team_member_roles(team_ids=recompute_team_ids)
    if object_roles_to_update:
        roles_to_recompute = ObjectRole.objects.filter(pk__in=[obj_role.pk for obj_role in object_roles_to_update]).prefetch_related(
            'provides_teams__has_roles'
        )
        recompute_role_evaluations(roles_to_recompute)


def _find_assignments(
    resolved: Sequence[ResolvedAssignment],
    lookup: ObjectRoleLookup,
    model: type[AssignmentBase],
    actor_field: str,
) -> list[AssignmentBase]:
    """Find existing assignments matching resolved triples via the ObjectRole lookup."""
    q = Q()
    for ra in resolved:
        obj_role = lookup.get((ra.role_definition.pk, ra.object_id))
        if obj_role is not None:
            q |= Q(object_role_id=obj_role.pk, **{actor_field: ra.actor.pk})
    if not q:
        return []
    return list(model.objects.filter(q))


def _recompute_after_remove(
    object_role_ids: set[int],
    actor_team_ids: set[int] = frozenset(),
) -> None:
    """Recompute permissions, expand team ancestors, and clean up orphaned ObjectRoles."""
    _check_defer_guard()
    object_roles = set(ObjectRole.objects.filter(pk__in=object_role_ids))
    recompute_team_ids = _collect_recompute_team_ids(object_roles)
    object_roles_to_update: set[ObjectRole] = set(object_roles)

    if actor_team_ids:
        snapshot = list(object_roles_to_update)  # snapshot: set is mutated in the loop
        for obj_role in snapshot:
            object_roles_to_update.update(obj_role.descendent_roles())
        object_roles_to_update.update(bulk_ancestor_roles(actor_team_ids))

    if recompute_team_ids:
        compute_team_member_roles(team_ids=recompute_team_ids)
    if object_roles_to_update:
        surviving_object_roles = ObjectRole.objects.filter(pk__in=[o.pk for o in object_roles_to_update])
        recompute_role_evaluations(surviving_object_roles)

    ObjectRole.objects.filter(id__in=object_role_ids, users__isnull=True, teams__isnull=True).delete()


def remove_assignments(
    user_assignments: Sequence[RoleUserAssignment] = (),
    team_assignments: Sequence[RoleTeamAssignment] = (),
    content_objects: dict[tuple[int, str], ContentObject] | None = None,
) -> None:
    """Remove assignments by reference and recompute affected permissions.

    Lower-level alternative to bulk_remove_permissions — accepts assignment objects
    directly, avoiding the triple resolution and GFK lookups that the bulk API requires.

    Args:
        content_objects: Optional dict mapping (content_type_id, object_id) to model instances.
            When provided, these are included in the bulk signal. When None, signal fires
            with None for content objects (consumer can fetch if needed).
    """
    if not user_assignments and not team_assignments:
        return

    # Always fire bulk signal BEFORE deletion with whatever content_objects we have (may be empty dict)
    all_assignments = list(user_assignments) + list(team_assignments)
    dab_rbac_assignments_pre_delete.send(
        sender=None,
        assignments=all_assignments,
        content_objects=content_objects or {},
    )

    object_role_ids: set[int] = set()
    actor_team_ids: set[int] = set()
    for a in user_assignments:
        object_role_ids.add(a.object_role_id)
    for a in team_assignments:
        object_role_ids.add(a.object_role_id)
        actor_team_ids.add(a.team_id)

    if user_assignments:
        RoleUserAssignment.objects.filter(pk__in=[a.pk for a in user_assignments]).delete()
    if team_assignments:
        RoleTeamAssignment.objects.filter(pk__in=[a.pk for a in team_assignments]).delete()

    _recompute_after_remove(object_role_ids, actor_team_ids)


def give_assignments(
    user_resolved: Sequence[ResolvedAssignment] = (),
    team_resolved: Sequence[ResolvedAssignment] = (),
    content_objects: dict[tuple[int, str], ContentObject] | None = None,
) -> list[AssignmentBase]:
    """Assign roles from already-resolved assignments (skips validation).

    Lower-level alternative to bulk_give_permissions — accepts ResolvedAssignment
    lists directly, for callers that have already resolved and validated.

    Returns only the *newly-created* assignments. Pairs that already existed are omitted:
    bulk_create(ignore_conflicts=True) cannot report skipped rows, and fetching them back
    is the query that does not scale. Callers needing pre-existing rows must fetch them.

    Args:
        content_objects: Optional dict mapping (content_type_id, object_id) to model instances.
            When provided, these are included in the dab_rbac_assignments_created signal.
            When None, the signal fires with an empty dict (consumer can fetch if needed).
    """
    if not user_resolved and not team_resolved:
        return []

    lookup = _ensure_object_roles(list(user_resolved) + list(team_resolved))
    created_assignments = _create_assignments(list(user_resolved), list(team_resolved), lookup)

    # Fire the bulk signal only when rows were actually created (idempotent re-gives are silent).
    if created_assignments:
        dab_rbac_assignments_created.send(
            sender=None,
            assignments=created_assignments,
            content_objects=content_objects or {},
        )

    _recompute_after_give(lookup, created_assignments)
    return created_assignments


def bulk_give_permissions(
    user_permissions: Sequence[PermissionTriple] = (),
    team_permissions: Sequence[PermissionTriple] = (),
) -> list[AssignmentBase]:
    """Convenience API: validates triples, resolves, and delegates to give_assignments.

    Returns only the newly-created assignments (see give_assignments for why).
    """
    if not user_permissions and not team_permissions:
        return []

    # Resolve and collect content_objects in one pass
    user_resolved, team_resolved, content_objects = _resolve_assignments(user_permissions, team_permissions, collect_content_objects=True)
    # Signal fires in give_assignments with the content_objects we pass
    return give_assignments(user_resolved, team_resolved, content_objects=content_objects)


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

    # Resolve and collect content_objects in one pass
    user_resolved, user_content_objects = _resolve_triples(user_permissions, collect_content_objects=True)
    team_resolved, team_content_objects = _resolve_triples(team_permissions, collect_content_objects=True)

    # Merge content_objects dicts
    content_objects = {**(user_content_objects or {}), **(team_content_objects or {})}

    lookup = _lookup_object_roles(user_resolved + team_resolved)
    if not lookup:
        return

    user_found = _find_assignments(user_resolved, lookup, RoleUserAssignment, 'user_id')
    team_found = _find_assignments(team_resolved, lookup, RoleTeamAssignment, 'team_id')
    # Signal fires in remove_assignments with the content_objects we pass
    remove_assignments(user_assignments=user_found, team_assignments=team_found, content_objects=content_objects)
