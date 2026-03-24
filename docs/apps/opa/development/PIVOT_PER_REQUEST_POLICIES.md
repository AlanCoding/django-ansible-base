# Pivot: From Full Sync to Policy Reference Model

**Date:** 2026-03-24

## What changed

The OPA integration was refactored from a **full user-policy sync** model
to a **policy reference** model. This happened in two steps.

### Before (full sync model)

1. When roles, policies, or group memberships changed, Django ran
   `sync_to_opa()` which traversed all `User -> OPAGroup -> Role -> Policy`
   relationships and built a flat lookup table:
   `user_id -> resource -> action -> [clauses]`
2. This entire table was pushed to OPA via `PUT /v1/data/dab_opa/user_policies`
3. Per-request, Django sent just `{principal, target}` to OPA
4. OPA looked up the user's policies from its stored data using
   `data.dab_opa.user_policies[user_id][resource][action]`

### After (policy reference model)

1. When a Policy is created, modified, or deleted, Django pushes **all
   policy definitions** to OPA via `PUT /v1/data/dab_opa/policies`, keyed
   by PK. This is lightweight -- policies are small clause dicts.
2. Per-request, Django resolves the user's effective policy IDs
   (`User -> OPAGroup -> GroupRoleAssignment -> Role -> Policy`) and sends
   just the list of IDs as `input.policy_ids`.
3. OPA looks up the referenced policies from its cached data and evaluates
   them against the Rego rules.

## Why

The full sync model had several drawbacks:

- **Stale data:** Between syncs, OPA served decisions based on outdated
  policies. Any change to groups/roles/assignments required a full resync.
- **All-users payload:** Every sync pushed data for every user, even though
  only one user's policies may have changed.
- **Data duplication:** When multiple users shared the same role, the clause
  data was duplicated per user in the synced payload.

The policy reference model improves on this:

- **Policy definitions rarely change.** Sync only happens on Policy CRUD.
  Group membership and role assignment changes take effect immediately
  because Django resolves `policy_ids` per-request.
- **No user data in OPA.** OPA only stores policy definitions (keyed by PK).
  No user-to-policy mappings.
- **Small per-request payload.** Instead of sending full clause dicts,
  Django sends a list of integer IDs. OPA looks them up.
- **No stale group/role data.** Since Django resolves which policies apply
  to a user at request time, group membership and role assignment changes
  take effect immediately.

## What was removed

- `sync_to_opa()` and all per-user sync infrastructure (`_do_sync`,
  `_push_to_opa`, `_write_data_json`, debounce timer)
- `generate_user_policies()` (all-users policy flattening)
- Signal handlers for Group, Role, and GroupRoleAssignment changes
  (only Policy signals remain)
- Admin "Sync to OPA" actions
- `sync_to_opa()` calls in API views' `perform_create/update/destroy`
- `sync_opa_fixture` test fixture

## What was kept

- `sync_policies_to_opa()` -- pushes policy definitions to OPA (replaces
  the old user-policy sync)
- `recompute_team_memberships()` -- still needed for org admin team
  inheritance
- `get_effective_policies()` in evaluator.py -- local evaluator path
- `get_user_policy_ids()` in evaluator.py -- per-request policy resolution
- Local evaluator -- unchanged, still performs identical evaluation in Django
- All data models (OPAGroup, Role, Policy, GroupRoleAssignment)
- Signal-based sync on Policy save/delete (via `connect_policy_sync_signals`)
