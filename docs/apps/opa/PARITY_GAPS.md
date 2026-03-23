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

**What RBAC does:** Beyond filtering querysets ("show me what I can see"),
RBAC also enforces permission checks against related objects during create and
update operations. Examples:

- **Creating an inventory in org X** requires `add_inventory` permission
  scoped to org X. This is a parent-object check — the inventory doesn't
  exist yet.
- **Assigning a credential to a job template** requires `use_credential`
  permission on the credential. This is a cross-resource check — you need
  permission on object A to use it in the context of object B.
- **Adding a user to a team** requires appropriate permission on the team.

These are all "can I do action A on object B in the context of object C?"
questions.

**What OPA does today:** OPA handles queryset filtering well — "show me all
inventories I can read" works correctly. But the system has no mechanism for
related-object checks. The `add` action is mapped in the migration, but the
semantics don't align: `add` in RBAC is "can I create a child object under
this parent", while in OPA it would need to be "does the user have a policy
granting `add` for this resource scoped to the parent object?"

**Impact:** High. Without this, users could create objects in orgs they
shouldn't, or use credentials they don't have permission for. This is a
fundamental authorization pattern in Ansible, not an edge case.

**Fix approach:** This requires both data model and evaluation changes:

1. **Parent-object checks for create:** When creating an inventory, the view
   needs to ask OPA "can user X `add` inventory scoped to organization Y?"
   The policy data already supports this (a policy with
   `resource=inventory, action=add, field_name=organization_id, value=Y`).
   What's missing is the view-level integration that extracts the parent
   object from the request and queries OPA with it.

2. **Cross-resource checks (use permissions):** These need a new pattern.
   When a job template references credential Z, the view needs to check
   "can user X `use` credential Z?" This is an object-level check on a
   different resource than the one being created/modified. OPA can evaluate
   this — it's just `resource=credential, action=use, target_id=Z` — but
   the view integration and the `use` action need to be wired up.

3. **View-level hooks:** `OPAPermission.has_permission()` (for create) and
   `has_object_permission()` (for update with related objects) need to
   extract related object references from the request payload and make
   additional OPA queries.

**This is the next implementation priority after the org admin inheritance
fix.**

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
3. **Related object permission checks** (Gap #2) — view-level integration
   for create/update with parent and cross-resource checks. This is
   structural and requires careful design. **This is the next priority.**
