# RBAC to OPA Migration Plan

## Overview

This document outlines the plan for migrating existing DAB RBAC permission data to the new DAB OPA app. The migration enables a path where the host app adds `dab_opa` to `INSTALLED_APPS`, runs a management command, and all existing permission assignments are translated into OPA roles, policies, and group assignments.

---

## 1. Migration command

The migration will be implemented as a Django management command in the `dab_opa` app:

```
python manage.py migrate_rbac_to_opa
```

This is a data migration command (not a Django schema migration) so it can be run manually and repeatedly during testing. It should be idempotent — running it twice produces the same result.

---

## 2. What gets migrated

### 2.1 RoleDefinitions -> OPA Roles + Policies

Each `RoleDefinition` in the old system becomes:

- An OPA `Role`
- A set of `Policy` rows attached to that role, one per (resource, action, scope) combination derived from the role definition's permissions and the object it was assigned to.

### 2.2 ObjectRole assignments -> OPAGroup + GroupRoleAssignment

Each `ObjectRole` with user/team assignments becomes:

- `RoleUserAssignment` entries -> the user's auto-created single-user `OPAGroup` gets a `GroupRoleAssignment` to the corresponding OPA `Role`.
- `RoleTeamAssignment` entries -> the team maps to an `OPAGroup` (teams become OPA groups), and that group gets a `GroupRoleAssignment`.

### 2.3 Teams -> OPAGroups

Each existing team becomes an `OPAGroup`. Users who were members of a team get membership in the corresponding `OPAGroup`.

### 2.4 Organizations as policy scope

Object-level role assignments scoped to an organization (e.g., "Organization Admin on org X") become policies with `organization_id == X` conditions.

Object-level role assignments scoped to a specific object (e.g., "Inventory Admin on inventory Y") become policies with `id == Y` conditions.

---

## 3. What does NOT get migrated

### 3.1 Creator roles

The old RBAC system has auto-created "creator" roles (e.g., `{model_name}-creator-permission`). These roles grant the creating user view/change/delete permissions on objects they created.

In the new OPA system, this is handled natively via the `created_by_id == principal_user_id` policy shape. The migration will **not** convert old creator role assignments into individual OPA roles. Instead:

- The new system's managed roles will include a standard "creator access" policy using `created_by_id == principal_user_id`.
- Old creator `ObjectRole` and `RoleUserAssignment` rows for creator roles are skipped during migration.
- The migration command should log that these were skipped and why.

### 3.2 Teams of teams

The old RBAC system supported hierarchical team membership (team A is a member of team B). In practice this was never allowed/used in real deployments. The migration will **ignore** any team-of-team relationships:

- `RoleTeamAssignment` entries where the target object is another team with `member_team` permission are skipped.
- `ObjectRole.provides_teams` transitive closure data is not migrated.
- The migration command should log if any team-of-team relationships are encountered and skipped.

### 3.3 RoleEvaluation cache tables

`RoleEvaluation` and `RoleEvaluationUUID` are computed cache tables in the old system. They are not migrated — the new system has no equivalent cache.

### 3.4 DABContentType / DABPermission

These are structural metadata in the old system. The new system uses settings-based resource/action registration instead of database-backed content types. These tables are not migrated.

---

## 4. Migration edge cases and special handling

### 4.1 Global/system-wide roles

Roles with `content_type=None` (system-wide roles like System Auditor) need special handling. These may map to OPA roles with policies that have no field constraints (effectively granting access to all objects of a resource type).

### 4.2 Managed vs custom roles

The old system distinguishes `managed=True` role definitions (system-created) from user-created ones. Both must be migrated, but managed roles in the new system may have a different structure. The migration should:

- Map known managed roles (Organization Admin, Organization Member, Team Admin, Team Member) to their OPA equivalents.
- Migrate custom role definitions as custom OPA roles.

### 4.3 Permission granularity mapping

The old system uses Django-style codename permissions (e.g., `view_inventory`, `change_inventory`). The new system uses resource + action pairs. The migration must map:

- `view_{model}` -> `(resource, "read")`
- `change_{model}` -> `(resource, "change")`
- `delete_{model}` -> `(resource, "delete")`
- `add_{model}` -> `(resource, "add")` (if supported)
- Custom permissions -> TBD based on resource registry

### 4.4 Superuser handling

Superuser bypass exists outside both systems. No migration needed for superuser flags.

---

## 5. Bootstrap script expansion

### 5.1 Goal

The `test_app/scripts/bootstrap.sh` and `test_app/management/commands/create_demo_data.py` must be expanded to create data covering all RBAC assignment types so the migration can be manually tested end-to-end.

### 5.2 Data to create

The demo data creator needs to produce:

- **Multiple organizations** with different teams and users.
- **Organization-scoped role assignments**: users and teams with Organization Admin, Organization Member roles on specific orgs.
- **Object-level role assignments**: users and teams with specific permissions on individual Inventories, InstanceGroups, etc.
- **Creator role assignments**: objects created by specific users (using `impersonate`) so that creator roles are auto-generated. These should be verifiable as skipped during migration.
- **Custom (non-managed) role definitions**: user-created role definitions with various permission combinations assigned to users and teams on specific objects.
- **Team membership**: users as members of teams, with those teams having role assignments, so the team -> OPAGroup path is exercised.
- **Cross-organization assignments**: users with roles in multiple organizations to verify multi-org policy generation.
- **Global/system-wide roles**: System Auditor assignments to verify system role migration.
- **Edge cases**: roles with overlapping permissions, users with both direct and team-inherited permissions on the same object.

### 5.3 Verification

After running the migration command, there should be a way to verify correctness:

- A `--dry-run` flag on the migration command that reports what would be created without writing.
- A `--verify` flag that compares effective permissions between the old RBAC system and the new OPA system for all users and reports discrepancies.
- Manual spot-checking via the Django admin or API.

---

## 6. Implementation phases

### Phase 1: Expand demo data

- Update `create_demo_data.py` to create comprehensive RBAC data as described in section 5.2.
- Verify all RBAC role types are represented in the test data.

### Phase 2: Migration command skeleton

- Create `dab_opa/management/commands/migrate_rbac_to_opa.py`.
- Implement reading of old RBAC data structures.
- Implement dry-run reporting.

### Phase 3: Core migration logic

- Team -> OPAGroup migration.
- User -> single-user OPAGroup creation.
- RoleDefinition -> Role + Policy translation.
- ObjectRole assignment -> GroupRoleAssignment creation.
- Creator role skipping with logging.
- Team-of-team skipping with logging.

### Phase 4: Verification tooling

- Implement `--verify` flag.
- Compare effective permissions old vs new for all users.
- Report on any discrepancies.

### Phase 5: Integration testing

- Automated tests that run the full migration on demo data and assert correctness.
- Tests that verify skipped creator roles still have equivalent access via `created_by_id` policies.
