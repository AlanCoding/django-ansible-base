# DAB OPA Parity Gaps

This document tracks the known differences between DAB RBAC and DAB OPA
authorization behavior. It categorizes each gap, explains why it matters (or
doesn't), and proposes next steps.

See [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) for completed phases and
[RBAC_REMOVAL.md](RBAC_REMOVAL.md) for the eventual RBAC removal plan.

---

## Status legend

| Status | Meaning |
|--------|---------|
| Non-issue | Feature was never used, or is inherently handled another way |
| Gap | Real difference in behavior that needs implementation work |
| Design problem | Requires architectural thinking, not just code |

---

## 1. Org admin inherits team permissions — Fixed

**What RBAC does:** When a user is Organization Admin on org X, they
implicitly inherit every permission held by every team in org X. This works
through the `provides_teams` M2M on `ObjectRole`. The caching system
(`caching.py`) discovers that the org admin role has the `member_team`
permission, populates `provides_teams` with all teams in that org, and then
`needed_cache_updates()` includes all permissions from those teams'
`has_roles` in the `RoleEvaluation` cache.

This means if `awx_devs` (a team in AWX_community) has Inventory Admin on
"Galaxy Host" (an inventory in Galaxy_community — a different org), the AWX
org admin gets `view_inventory` + `change_inventory` on Galaxy Host.

**How OPA handles it:** During migration, when the command processes an
org-level user assignment, it checks whether the role definition has the
`member_team` permission. If so, it adds the user to every team's OPA group
in that organization. This way, the org admin inherits team permissions
through OPA group membership — no policy duplication needed.

See `_inherit_team_memberships()` in `migrate_rbac_to_opa.py`.

**Tests:** 3 tests in `test_migration.py`:
- `test_org_admin_inherits_team_permissions` — cross-org team permission
  inheritance works
- `test_org_admin_team_inherit_matches_rbac` — OPA and RBAC agree
- `test_non_member_team_role_no_inheritance` — org member (without
  `member_team`) does NOT inherit

**Remaining concern:** This is solved for migration, but the ongoing case
is covered under gap #3 (new team creation requires updating org admin
group memberships).

---

## 2. Related object permission checks — Gap

This gap is part of a broader architectural change: separating OPA
evaluation into two tiers.

### Two-tier evaluation architecture

**Tier 1: Queryset filtering (list operations)**

OPA returns *clauses* — field/operator/value tuples that Django compiles
into `Q()` filters. This is "partial evaluation" and is a best-effort
approach. It is optimized for performance: the goal is to filter a
queryset down to a reasonable set, not to be the final authority.

In the future, DENY policies may be excluded from clause generation to
avoid blowing up querysets. This means tier 1 may over-include — some
objects in the filtered queryset might not actually be accessible. This
is acceptable because tier 2 is the authoritative check.

Input (unchanged from today):
```json
{"input": {
  "principal": {"user_id": 6, "is_superuser": false},
  "target": {"resource": "inventory", "action": "read"}
}}
```
Response: `{"allow": true, "clauses": [...]}`

**Tier 2: Object evaluation (single object + action)**

For a specific "can user X do action Y on object Z?", the object's actual
attributes are sent to OPA, and OPA returns a concrete boolean. This is
the *canonical* answer. It can evaluate DENY rules, check related objects,
and be arbitrarily complex without worrying about queryset representation.

Input (new):
```json
{"input": {
  "principal": {"user_id": 6, "is_superuser": false},
  "target": {"resource": "inventory", "action": "change"},
  "object": {"id": 42, "organization_id": 1, "credential_id": 5},
  "related": {
    "organization": {"resource": "organization", "action": "add", "id": 2},
    "credential": {"resource": "credential", "action": "use", "id": 5}
  }
}}
```
Response: `{"allow": true}` or `{"allow": false, "denied_fields": ["credential"]}`

The `object` field contains the target object's attributes (the fields
registered in the OPA registry). The Rego rules evaluate the user's
clauses against these specific attribute values rather than returning
clauses for queryset construction.

The `related` field contains related objects being set or changed. Each
entry specifies which resource and action to check, plus the related
object's ID. OPA evaluates each related check against the user's policies
for that resource/action.

**Currently**, `user_can_access_obj()` fakes tier 2 by running tier 1
(getting clauses) and checking if the object would match. This must change
to use a real tier 2 OPA evaluation with the object's data in the input.

### What RBAC does for related objects

Beyond filtering querysets, RBAC enforces permission checks against related
objects during create and update operations via `RelatedAccessMixin`:

- **Creating an inventory in org X** requires `add_inventory` permission
  scoped to org X. This is a parent-object check — the inventory doesn't
  exist yet.
- **Assigning a credential to a job template** requires `use_credential`
  permission on the credential. This is a cross-resource check — you need
  permission on object A to use it in the context of object B.
- **Adding a user to a team** requires appropriate permission on the team.

The action required for each FK field is determined by
`required_related_permission()` in `ansible_base/rbac/api/related.py`:
- **Parent FK** (e.g., `organization`): requires `add_{model_name}`
- **Non-parent FK** (e.g., `credential`): requires the first matching
  action from `ANSIBLE_BASE_CHECK_RELATED_PERMISSIONS` (default:
  `['use', 'change', 'view']`)

### Impact

High. Without this, users could create objects in orgs they shouldn't, or
use credentials they don't have permission for. This is a fundamental
authorization pattern in Ansible, not an edge case.

### Implementation plan

**1. Rego rules for tier 2 evaluation**

Add rules that evaluate `input.object` against user clauses directly:

```rego
# Tier 2: object evaluation — does a specific object match the user's clauses?
object_allowed if {
    input.principal.is_superuser == true
}

object_allowed if {
    user_id := format_int(input.principal.user_id, 10)
    policies := data.dab_opa.user_policies[user_id][input.target.resource][input.target.action]
    some p in policies
    clause := _resolve_clause(p)
    input.object[clause.field_name] == clause.value
}

# Related object checks
related_denied[field] := reason if {
    some field, check in input.related
    not _related_allowed(check)
    reason := concat("", ["No ", check.action, " permission on ", check.resource])
}

_related_allowed(check) if {
    input.principal.is_superuser == true
}

_related_allowed(check) if {
    user_id := format_int(input.principal.user_id, 10)
    policies := data.dab_opa.user_policies[user_id][check.resource][check.action]
    some p in policies
    clause := _resolve_clause(p)
    clause.field_name == "id"
    clause.value == check.id
}

# Also allow org-scoped related checks (e.g., add_inventory scoped to org)
_related_allowed(check) if {
    user_id := format_int(input.principal.user_id, 10)
    policies := data.dab_opa.user_policies[user_id][check.resource][check.action]
    some p in policies
    clause := _resolve_clause(p)
    clause.field_name == "organization_id"
    clause.value == check.org_id
}
```

The existing `allow` / `clauses` rules remain for tier 1. A new
`object_allowed` rule handles tier 2 when `input.object` is present.

**2. OPA client**

Extend `OPAClient` with a `check_object()` method that sends
`input.object` and `input.related` and returns a boolean + denied fields.

**3. Local evaluator**

Extend the local evaluator with equivalent logic: evaluate clauses
against the object's attributes, check related objects against user
policies.

**4. View integration (`OPARelatedAccessMixin`)**

A serializer mixin (replacing RBAC's `RelatedAccessMixin`) that:
- On `create()`: builds `input.object` from the created instance's
  attributes, builds `input.related` from FK fields using
  `required_related_permission()` logic, calls tier 2 OPA evaluation.
- On `update()`: compares old vs new FK values (only changed FKs go
  into `related`), calls tier 2 OPA evaluation.

**5. `user_can_access_obj()`**

Change from "filter queryset, check membership" to a real tier 2 OPA
call. The object's registered fields are extracted and sent as
`input.object`.

**6. Tests**

The gap tests in `test_related_permissions.py` should start failing
(related checks now enforced). New tests for tier 2 evaluation directly.

### Implementation order

1. Rego rules (tier 2 evaluation + related checks)
2. OPA client + local evaluator extensions
3. `user_can_access_obj()` refactored to use tier 2
4. `OPARelatedAccessMixin` for serializers
5. Wire up in test_app, tests

**This is the next implementation priority.**

---

## 3. Org admin team membership maintenance — Implemented (recompute-before-sync)

Gap #1 (migration-time team inheritance) is fixed. The runtime maintenance
concern is now handled by `recompute_team_memberships()` in `sync.py`,
which runs before every OPA sync.

**The problem at migration time:** Solved. The migration adds org admin users
to all existing team OPA groups in their org. When team permissions change
after migration, the org admin already belongs to the team's OPA group, so
they automatically inherit the new permissions. No recomputation needed.

**The problem at runtime:** Multiple events can change whether a user should
be a member of a team's OPA group. All of them need to trigger a group
membership update:

### Events that require group membership updates

1. **New team created** in org X → find all org admin users of org X, add
   them to the new team's OPA group.

2. **User becomes org admin** (GroupRoleAssignment created linking a user's
   group to an org admin role) → add the user to all team OPA groups in
   that org.

3. **User added to an OPA group** that already has an org admin role for
   org X → add the user to all team OPA groups in X.

4. **Role assigned to a group** (GroupRoleAssignment) where users already
   exist and the role is org-admin-like → add all existing users in the
   group to team OPA groups.

5. **Policy added to an OPA role** that makes it org-admin-equivalent
   (e.g., adding `member_team`-equivalent semantics) → find all users with
   that role, add them to team groups. (This is the most exotic case.)

This is the same set of triggers RBAC handles through `compute_team_member_roles()`
and the signal handlers in `triggers.py` — `post_save` on teams,
`permissions_changed` on role definitions, `m2m_changed` on ObjectRole.users.

### The "org admin-like" detection problem

In RBAC, org admin roles are identified by having the `member_team`
permission. The OPA system has no equivalent semantic marker. Migrated roles
have names like `rbac:Organization Admin@org:1`, but that's a naming
convention, not something the system can reason about.

To implement eager expansion, the OPA system needs a way to mark roles as
"grants team membership in org X." Options:

- **Explicit marker on the Role model:** Add a field like
  `grants_team_membership = True` or `team_membership_org = FK(Organization)`.
  The migration sets it; the signal handlers check it.
- **Convention-based detection:** Check if a role has policies granting
  `change` + `delete` on `team` scoped to a specific org. Fragile.
- **Separate M2M or through-model:** An `OrgAdminGrant` model that
  explicitly records "this role makes users org admins of org X."

### The broader philosophical question

Consider "who can edit inventory B?" OPA returns users who currently have
`change` permission on inventory B. But an org admin of the org containing a
team with Inventory Admin on B could add themselves to that team and *then*
edit B. In RBAC, this user already shows up because their permissions are
eagerly expanded. In OPA, whether they show up depends on whether the team
membership was propagated.

More broadly: any event that results in a user gaining org-admin-equivalent
access should cascade into team group membership. This is a graph problem —
the permission graph has edges from role assignment → group membership →
team membership, and a change at any node can affect downstream nodes.

### Options

#### Option A: Eager expansion via signals

Add Django signal handlers for all five events listed above. Each handler
checks whether the change affects org-admin-level access and updates team
OPA group memberships accordingly.

This matches RBAC's approach (`triggers.py` + `compute_team_member_roles()`).

- **Pro:** "Who can edit inventory B?" is always accurate
- **Pro:** Matches current RBAC behavior exactly
- **Pro:** No policy duplication — org admin is a group member, not a
  policy holder
- **Pro:** When the team gets new permissions, the org admin automatically
  inherits them (no recomputation of policies)
- **Con:** Requires signal handlers on 5 different events
- **Con:** Needs a way to identify "org admin-like" roles (new model field
  or convention)
- **Con:** Signal cascades can be complex — e.g., adding a policy to a role
  triggers checking all groups with that role, all users in those groups,
  all orgs affected, all teams in those orgs
- **Con:** During the transition period (both systems active), the signals
  need to keep both RBAC and OPA in sync

#### Option B: Periodic recomputation

Instead of signals, run a periodic task (or pre-sync hook) that
recomputes all org-admin-to-team group memberships from scratch before
every OPA sync.

- **Pro:** Simple — one function, no signal wiring
- **Pro:** Always consistent (full recompute, no missed edges)
- **Con:** Permissions are stale between syncs
- **Con:** O(users × orgs × teams) per recompute (acceptable at our scale)

#### Option C: Hybrid — org admin override in Rego

Add a Rego rule that says "if user is org admin of org X, grant all
permissions that any team in org X has." This requires pushing
team-permission mappings to OPA alongside user policies.

- **Pro:** Compact — one rule per org admin, not one group membership per
  team
- **Pro:** Automatically handles all five events without any signals
- **Pro:** No "org admin-like" detection needed — the Rego rule is explicit
- **Con:** Adds complexity to Rego (currently a simple key lookup)
- **Con:** Requires team→permission data in OPA (more data to sync)
- **Con:** Moves authorization logic back into OPA (away from
  "pre-flattened lookup" design)

#### Option D: Accept the gap

Acknowledge that OPA requires explicit group membership, and that admin
actions affecting team membership require a sync step.

- **Pro:** Simplest
- **Con:** Behavior regression from RBAC
- **Con:** Easy to forget

### Current implementation: Option B (recompute before sync)

`recompute_team_memberships()` in `ansible_base/opa/rego/sync.py` runs
before every OPA sync. It:

1. Finds all OPA policies granting `change` on `team` scoped to an org
   (i.e., `resource=team, action=change, field_name=organization_id`)
2. Traces each policy back through role → group → users to find all users
   who can modify teams in that org
3. For each such user, ensures they are a member of every team OPA group
   in that org

This avoids the "org admin-like" detection problem entirely — it doesn't
care about role names or conventions. It asks the concrete question: "who
has a policy that lets them change teams in org X?" Those users get added
to team groups.

The function is idempotent and handles all five events listed above,
because it recomputes from scratch every time. The trade-off is that
permissions are stale between syncs — if a new team is created and the
sync hasn't run yet, the org admin won't be in that team's group until
the next sync.

**Tests:** 3 tests in `test_migration.py`:
- `test_recompute_adds_user_to_new_team` — new team created after
  migration, recompute adds org admin
- `test_recompute_idempotent` — running twice doesn't duplicate
- `test_recompute_skips_non_team_changers` — users who can only read
  teams are not added

### Future optimization: Option A (signals)

If the sync latency gap is unacceptable, signal-driven updates can be
added later. The signal surface is large (five events), but the logic
is the same — just triggered incrementally instead of as a full
recompute.

---

## 4. Teams-in-teams — Non-issue

**What RBAC does:** Teams can be members of other teams, creating recursive
permission inheritance. This is controlled by `ANSIBLE_BASE_ALLOW_TEAM_PARENTS`.

**Status:** This feature has never been used in any production deployment.
The setting defaults to disabled. All RBAC code and tests for this feature
remain untouched — the OPA work does not modify any RBAC code.

**OPA stance:** Not supported. Not planned. If teams-in-teams were ever
enabled in a deployment, migration would need to flatten the recursive
membership, but this is not a practical concern.

---

## 5. Extra bypass flags — Non-issue

**What RBAC does:** `ANSIBLE_BASE_BYPASS_SUPERUSER_FLAGS` can list additional
user model fields (beyond `is_superuser`) that grant full access.
`ANSIBLE_BASE_BYPASS_ACTION_FLAGS` maps specific actions to user flags (e.g.,
`is_platform_auditor` grants all `view_*` permissions).

**Status:** `BYPASS_SUPERUSER_FLAGS` defaults to `['is_superuser']` and no
downstream app adds others. `BYPASS_ACTION_FLAGS` defaults to `{}` and was
used once historically but no longer. The OPA Rego checks `is_superuser`
only.

**OPA stance:** Not supported. If a downstream app ever needs additional
bypass flags, the Rego rules can be extended to check them. This is a
straightforward Rego change, not a design problem.

---

## 6. Creator/owner permissions — Non-issue

**What RBAC does:** Creator permissions are not tracked in `RoleEvaluation`.
They're handled by individual views checking `created_by` or by explicit
role assignments made at object creation time.

**OPA stance:** Handled natively via `value_type=principal_user_id` policies.
A policy like `resource=inventory, action=read, field_name=created_by_id,
value_type=principal_user_id` means "users can read inventories they
created." This is more elegant than RBAC's approach and requires no special
migration.

---

## 7. Migration is point-in-time — Non-issue

**Concern:** If new RBAC assignments are created after migration but before
RBAC is removed, they won't appear in OPA.

**Status:** Migration is an all-at-once process. The plan is: migrate, verify,
switch over, remove RBAC. There is no extended period where both systems
accept writes. The transition validation (Phase 9) catches runtime
discrepancies during the switchover period.

---

## Priority order for remaining work

1. ~~**Org admin team inheritance** (Gap #1)~~ — **Done.** Migration adds
   org admin users to team OPA groups. Verified with 3 tests including
   RBAC parity comparison.
2. ~~**Org admin team membership maintenance** (Design problem #3)~~ —
   **Done.** `recompute_team_memberships()` runs before every sync,
   finding users with `team/change` policies and adding them to team
   groups. Verified with 3 tests.
3. **Two-tier evaluation + related object checks** (Gap #2) — Separate
   OPA evaluation into queryset filtering (tier 1, clauses, best effort)
   and object evaluation (tier 2, boolean, authoritative). Tier 2 includes
   related object checks for create/update. Requires Rego rules, client
   extensions, view integration. **This is the next priority.**
