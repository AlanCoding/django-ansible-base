# Pivot: Per-Request Policy Passing

**Date:** 2026-03-24

## What changed

The OPA integration was refactored from a **sync-and-query** model to a
**per-request policy passing** model.

### Before (sync model)

1. When roles, policies, or group memberships changed, Django ran
   `sync_to_opa()` which traversed all `User -> OPAGroup -> Role -> Policy`
   relationships and built a flat lookup table:
   `user_id -> resource -> action -> [clauses]`
2. This entire table was pushed to OPA via `PUT /v1/data/dab_opa/user_policies`
3. Per-request, Django sent just `{principal, target}` to OPA
4. OPA looked up the user's policies from its stored data using
   `data.dab_opa.user_policies[user_id][resource][action]`

### After (per-request model)

1. No sync step. OPA stores no policy data.
2. Per-request, Django resolves the user's effective policies
   (`User -> OPAGroup -> Role -> Policy`), deduplicates them, and sends
   them as `input.policies` alongside `{principal, target}`.
3. OPA evaluates the policies it receives in each request. It is a
   stateless evaluator.

## Why

The sync model had several drawbacks:

- **Stale data:** Between syncs, OPA served decisions based on outdated
  policies. Any change required a full resync.
- **All-users payload:** Every sync pushed data for every user, even though
  only one user's policies may have changed.
- **Data duplication:** When multiple users shared the same role, the clause
  data was duplicated per user in the synced payload.
- **Conceptual mismatch:** The design spec (APP_DESIGN.md section 2.7) says
  "OPA receives effective policies, not roles" and "Django resolves
  user -> groups -> roles -> policies, then sends effective policies to OPA."
  The sync model deviated from this by pre-loading everything.

The per-request model aligns with the original design intent:

- **No stale data:** Policies are resolved fresh on every request.
- **No sync infrastructure:** No debouncing, no signals triggering sync,
  no threading, no data push.
- **OPA is stateless:** It evaluates what it's given. No stored state to
  manage or debug.
- **Simpler Rego:** Rules iterate over `input.policies` instead of indexing
  into stored data.

## What was removed

- `sync_to_opa()` and all sync infrastructure (`_do_sync`, `_push_to_opa`,
  `_write_data_json`, debounce timer)
- `generate_user_policies()` (all-users policy flattening)
- Signal handlers that triggered sync on model changes
- Admin "Sync to OPA" actions
- `sync_to_opa()` calls in API views' `perform_create/update/destroy`
- `sync_opa` management command (repurposed to health check)
- `sync_opa_fixture` test fixture

## What was kept

- `recompute_team_memberships()` — still needed for org admin team
  inheritance, but moved out of sync context
- `get_effective_policies()` in evaluator.py — became the core function
  used by both OPA and local paths
- Local evaluator — unchanged, still performs identical evaluation in Django
- All data models (OPAGroup, Role, Policy, GroupRoleAssignment)
