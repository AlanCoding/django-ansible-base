# DAB OPA Development Plan

## Overview

This is the implementation plan for the `dab_opa` app, the OPA service infrastructure, the RBAC migration, and the transition validation period. Work is organized into phases with dependencies noted.

---

## Phase 0: Infrastructure

**Goal**: OPA runs as a service alongside test_app development.

### 0.1 OPA in Docker image

- Add OPA binary installation to the root `Dockerfile` (pinned version, static binary from GitHub releases).
- Verify the binary works inside the container.

### 0.2 docker-compose service

- Add `opa` service to `docker-compose.yml` reusing the test_app image.
- Expose port 8181, mount repo for Rego bundle access.
- Add healthcheck.

### 0.3 Makefile targets

- Add `make opa` and `make stop-opa` targets following the `make postgres` pattern.

### 0.4 Bootstrap script

- Update `test_app/scripts/bootstrap.sh` to start OPA alongside PostgreSQL.

### 0.5 Placeholder Rego bundle

- Create `ansible_base/opa/bundles/` directory with a minimal placeholder Rego policy that accepts requests and returns empty clauses. This lets the infrastructure work end-to-end before real policy generation exists.

**Deliverable**: `make opa` starts OPA, `curl localhost:8181/health` returns OK, test_app can be configured to point at it.

---

## Phase 1: App skeleton and settings

**Goal**: `dab_opa` app exists and can be added to `INSTALLED_APPS`.

### 1.1 Create app structure

```
ansible_base/opa/
    __init__.py
    apps.py
    models/
        __init__.py
    management/
        __init__.py
        commands/
            __init__.py
    api/
        __init__.py
    rego/
        __init__.py
    bundles/          # Rego policy files (mounted into OPA container)
```

### 1.2 Settings schema

- Define `DAB_OPA` settings dict structure (resources, actions, fields, shared_fields).
- Add `ANSIBLE_BASE_ORGANIZATION_MODEL` setting (similar to `ANSIBLE_BASE_TEAM_MODEL`).
- Add `DAB_OPA_SERVER_URL` setting (default `http://localhost:8181`).
- Add `DAB_OPA_TRANSITION_VALIDATION` setting (default `False`).
- Implement settings loader and validation (reject invalid resource/action/field configs at startup).

### 1.3 test_app integration

- Add `dab_opa` to test_app's `INSTALLED_APPS`.
- Configure `DAB_OPA` settings with test_app's models (Organization, Team, Inventory, InstanceGroup).
- Set `ANSIBLE_BASE_ORGANIZATION_MODEL = 'test_app.Organization'`.

**Deliverable**: App loads without errors. Settings are validated at startup.

---

## Phase 2: Data model

**Goal**: All OPA models exist and have migrations.

### 2.1 OPAGroup

- `name` (CharField)
- `organization` FK (to `ANSIBLE_BASE_ORGANIZATION_MODEL`, via `settings` for lazy resolution)
- `users` M2M (to `settings.AUTH_USER_MODEL`, `related_name='dab_opa_groups'`)
- `managed` boolean (for system-generated groups like per-user groups)
- Standard timestamps

### 2.2 Role

- `name` (CharField, unique)
- `description` (TextField)
- `managed` boolean
- Standard timestamps

### 2.3 Policy

- `role` FK to `Role`
- `resource` CharField
- `action` CharField
- `field_name` CharField
- `operator` CharField (enum: `eq`)
- `value_type` CharField (enum: `constant`, `principal_user_id`)
- `constant_value` TextField (nullable)
- `position` IntegerField (optional ordering)
- Standard timestamps

### 2.4 GroupRoleAssignment

- `group` FK to `OPAGroup`
- `role` FK to `Role`
- Unique together: `(group, role)`
- Standard timestamps

### 2.5 Auto per-user OPAGroup

- Signal on user creation to ensure a single-user `OPAGroup` exists.
- Naming convention: `user:{pk}` or `user:{username}`, marked `managed=True`.

**Deliverable**: `manage.py migrate` creates all tables. Models have basic admin registration.

---

## Phase 3: Policy validation

**Goal**: Policies are validated against the settings registry and actual Django model fields.

### 3.1 Registry validation

- Validate `resource` against `DAB_OPA["resources"]`.
- Validate `action` against resource's allowed actions.
- Validate `field_name` against resource-specific fields + shared_fields.
- Validate `operator` against field's allowed operators.

### 3.2 Value validation

- For `value_type=constant`: resolve target model from settings, resolve Django field, coerce and validate `constant_value`.
- For `value_type=principal_user_id`: ensure `constant_value` is null/blank.

### 3.3 Action dependency validation

- Implement strict mode: reject policy if dependent action's corresponding policy is missing.
- Implement loose mode: auto-add required policies.
- Configurable default via `DAB_OPA["strict_mode_default"]`.

**Deliverable**: Invalid policies are rejected with clear error messages. Dependency enforcement works in both modes.

---

## Phase 4: Rego generation

**Goal**: Django generates Rego policy from the data model and pushes it to OPA.

### 4.1 Rego generator

- Module that reads all `OPAGroup` memberships, `GroupRoleAssignment`s, `Role`s, and `Policy` rows.
- Generates a complete Rego policy file encoding:
  - User -> group -> role -> policy resolution (pre-flattened).
  - `is_superuser` bypass rule.
  - `principal_user_id` substitution.
  - OR combination of matching policies per (user, resource, action).
- Output: one or more `.rego` files written to `ansible_base/opa/bundles/`.

### 4.2 OPA sync

- Function to push generated Rego to OPA (via OPA REST API or by writing to the bundle directory and triggering a reload).
- Django signals on `Policy`, `Role`, `GroupRoleAssignment`, and `OPAGroup.users` M2M changes trigger regeneration.
- Debounce/batch logic to avoid regenerating on every individual change during bulk operations.

### 4.3 Management command

- `manage.py sync_opa` — force-regenerate and push Rego to OPA. Useful for debugging and initial setup.

**Deliverable**: Changing a role/policy/assignment in Django results in OPA having the correct policy. `manage.py sync_opa` works.

---

## Phase 5: OPA client and queryset integration

**Goal**: Django can ask OPA "what can user X do with resource Y?" and apply the answer as a queryset filter.

### 5.1 OPA client

- HTTP client that sends `{principal, target}` to OPA and receives resolved clauses.
- Configurable via `DAB_OPA_SERVER_URL`.
- Error handling: if OPA is unreachable, deny all (fail closed).

### 5.2 Queryset compiler

- Takes resolved clauses from OPA.
- Maps `field_name` to `django_path` using registry metadata.
- Compiles clauses to `Q(...)` expressions ORed together.
- Empty clauses -> `.none()`.

### 5.3 Helper APIs

- `filter_queryset_for_user(queryset, user, action)` — main entry point.
- `user_can_access_obj(user, obj, action)` — derived from queryset filtering.
- `get_opa_scope(user, resource, action)` — raw OPA response for debugging.

### 5.4 Local evaluator

- Pure-Django evaluator that produces the same `Q(...)` without calling OPA.
- Used in tests (all tests require OPA, but this is the parity-check reference).
- Same API surface as OPA client path.

**Deliverable**: `filter_queryset_for_user()` works end-to-end through OPA. Local evaluator produces identical results.

---

## Phase 6: Host app integration hooks

**Goal**: DAB OPA plugs into the same locations as old RBAC.

### 6.1 Permission mixins

- Replacements for `AccessRelatedMixin` and similar RBAC view mixins.
- Same hook points in DRF views: `get_queryset()` filtering, `has_object_permission()`.
- These should be drop-in replaceable — same method signatures, different implementation.

### 6.2 Creator permission handling

- On object creation, no explicit role assignment needed (unlike old RBAC).
- The standard `created_by_id == principal_user_id` policy handles this generically.
- Verify that `created_by` field is set correctly on object creation.

### 6.3 test_app wiring

- Replace all RBAC imports/usage in test_app with OPA equivalents.
- Remove teams-of-teams test data and any related test_app behavior.
- Verify test_app works end-to-end with OPA.

**Deliverable**: test_app uses OPA for all permission checks. Old RBAC code in test_app is removed.

---

## Phase 7: API

**Goal**: New REST API for managing OPA roles, policies, groups, and assignments.

### 7.1 Endpoints

- `OPAGroup` CRUD
- `Role` CRUD (with nested policy management)
- `Policy` CRUD (scoped under roles)
- `GroupRoleAssignment` CRUD
- User effective permissions / scope introspection endpoint

### 7.2 Serializers

- Policy creation validates against registry (reuses Phase 3 validation).
- Role editing supports strict/loose mode via request parameter.
- Loose mode responses include auto-added policies.

### 7.3 Permissions on the API itself

- Who can manage roles and policies? This is a bootstrapping question.
- Likely: superusers can do everything, org admins can manage within their org.

**Deliverable**: Full API for managing OPA authorization data.

---

## Phase 8: RBAC migration

**Goal**: Management command migrates all old RBAC data to OPA.

### 8.1 Expand demo data

- Update `create_demo_data.py` to create comprehensive RBAC data:
  - Multiple orgs, teams, users.
  - All managed role types assigned.
  - Custom role definitions with various permissions.
  - Creator roles (via `impersonate`).
  - Object-level and org-level assignments.
  - Cross-org assignments.
  - System Auditor assignments.
  - Overlapping permissions.

### 8.2 Migration command

- `manage.py migrate_rbac_to_opa`
- Reads old RBAC models: `RoleDefinition`, `ObjectRole`, `RoleUserAssignment`, `RoleTeamAssignment`.
- Creates OPA equivalents lazily (only when assignments exist).
- Skips creator roles (logs reason).
- Skips team-of-team relationships (logs reason).
- Maps Django permission codenames to OPA (resource, action) pairs.
- Supports `--dry-run` (report only, no writes).
- Idempotent — safe to run multiple times.

### 8.3 Rego regeneration after migration

- After migration completes, trigger a full `sync_opa` to push all new data to OPA.

**Deliverable**: `manage.py migrate_rbac_to_opa` converts all demo data correctly. OPA has the correct policy loaded.

---

## Phase 9: Transition validation

**Goal**: Prove OPA produces the same results as old RBAC before removing it.

### 9.1 Dual-evaluation mode

- When `DAB_OPA_TRANSITION_VALIDATION = True`, both systems evaluate every request.
- OPA result is authoritative.
- Old RBAC result is computed for comparison.
- Discrepancies are logged with full context.

### 9.2 Verification command

- `manage.py migrate_rbac_to_opa --verify`
- Iterates all users, all resources, all actions.
- Compares effective permissions between old RBAC and new OPA.
- Reports discrepancies.

### 9.3 Validation sign-off

- Run verification against demo data.
- Run verification against any real-world data snapshots available.
- Once no discrepancies exist, the transition is validated.

**Deliverable**: Confidence that OPA produces identical authorization results to old RBAC.

---

## Next: Parity gaps and remaining work

> Phases 0-9 establish the OPA system, migration path, and transition
> validation. Before downstream adoption and RBAC removal, several parity
> gaps must be addressed.
>
> See **[PARITY_GAPS.md](PARITY_GAPS.md)** for the full analysis, including:
> - Org admin inheriting team permissions (migration gap)
> - Related object permission checks for create/update (implementation gap)
> - Acquirable permissions and "who can?" queries (design problem)
> - Features intentionally not supported (teams-in-teams, extra bypass flags)

---

## Phase 10: Remove DAB RBAC (future — not part of this patch)

> **This phase cannot be completed as part of the DAB OPA patch.**
> Before `ansible_base.rbac` can be removed, every downstream application
> that depends on it (AWX, Gateway, EDA, etc.) must first migrate to DAB OPA.
> That migration work happens in each downstream repo, not here.
>
> See **[RBAC_REMOVAL.md](RBAC_REMOVAL.md)** for the full removal plan and
> prerequisites for downstream applications.

---

## Dependency graph

```
Phase 0 (Infrastructure)
    |
Phase 1 (App skeleton)
    |
Phase 2 (Data model)
    |
Phase 3 (Policy validation)
    |
Phase 4 (Rego generation) ----+
    |                          |
Phase 5 (OPA client/queryset)  |
    |                          |
Phase 6 (Host app hooks)      |
    |                          |
Phase 7 (API)                  |
    |                          |
Phase 8 (RBAC migration) -----+
    |
Phase 9 (Transition validation)
    |
Phase 10 (Remove RBAC) ← future, requires downstream migration first
```

Phases 0-3 are sequential prerequisites. Phases 4-7 can partially overlap (e.g., API serializers can start once models exist, even before Rego generation is complete). Phase 8 requires Phases 2, 4, and the old RBAC data model. Phase 9 requires Phase 8 plus the host app hooks from Phase 6.

---

## Key decisions captured

| Decision | Rationale |
|----------|-----------|
| OPA runs one instance per node (sidecar) | Matches production deployment model |
| Rego is dynamically generated from Django data | OPA evaluates pre-compiled policy efficiently; no per-request policy resolution needed |
| M2M defined on OPAGroup, not User model | Host apps don't need to modify their User model |
| `ANSIBLE_BASE_ORGANIZATION_MODEL` setting | OPAGroup needs org FK; follows `ANSIBLE_BASE_TEAM_MODEL` pattern |
| Creator roles not migrated as roles | Handled natively by `created_by_id == principal_user_id` policy |
| Teams-of-teams ignored | Never used in practice |
| Lazy role creation during migration | Only create OPA roles when assignments actually exist |
| All tests require OPA | No separate test tiers; OPA is always running |
| Transition validation period | Dual-eval mode proves parity before removing old RBAC |
| New API, not backward-compatible | Old RBAC API dies with the old app |
| `add` is a supported action | Creation permissions map to `(resource, "add")` |
