# DAB OPA Endpoint Access Control

This document describes who can access the DAB OPA management endpoints.

## Core rule

**You can delegate access to any resource you have `change` on.**

If you have `change` on inventory 42, you can create policies granting
`read`, `change`, or `delete` on inventory 42 to others. If you have
org-scoped `change` on inventories in org 5, you can delegate any action
on inventories in org 5 (org-scoped or narrower).

You cannot delegate broader access than you hold.

## Endpoint access summary

### Roles (`/opa/roles/`)

| Operation | Who can do it |
|---|---|
| Create | Any authenticated user |
| List/Read | Any authenticated user |
| Update | Creator or superuser (managed roles: superuser only) |
| Delete | Creator or superuser (managed roles: superuser only) |

Roles are inert containers — creating one grants nothing. The gates
are on policy creation and role assignment. The `created_by` field
tracks ownership.

### Policies (`/opa/policies/`)

| Operation | Who can do it |
|---|---|
| Create | User has `change` covering the policy's scope |
| List/Read | Any authenticated user |
| Update | Not allowed (policies are immutable) |
| Delete | User has `change` covering the policy's scope, or superuser |

**Scope validation on create:**

- `field_name=id, value=X`: user must have `change` on the specific
  object (checked via `user_can_access_obj`).
- `field_name=organization_id, value=X`: user must have org-scoped
  `change` for that resource in org X. An id-scoped change on one
  object in the org is NOT sufficient (prevents privilege escalation).
- `value_type=principal_user_id`: superuser only.

### Groups (`/opa/groups/`)

OPAGroup is registered as an OPA-managed resource (`opagroup`). Access
is controlled by OPA policies on the `opagroup` resource.

| Operation | Who can do it |
|---|---|
| Create | User has `opagroup.add` scope |
| List/Read | Filtered to groups user has `opagroup.read` on |
| Update | User has `opagroup.change` on the group |
| Delete | User has `opagroup.change` on the group (managed groups: denied) |
| Add user | User has `opagroup.change` on the group |
| Remove user | User has `opagroup.change` on the group |

### Assignments (`/opa/assignments/`)

| Operation | Who can do it |
|---|---|
| Create | User has `change` on the group AND `change` covering all policies in the role |
| List/Read | Any authenticated user |
| Update | Not allowed (immutable) |
| Delete | User has `change` on the group |

**Dual gate on create:** assigning a role to a group is simultaneously
a group management action (changing what the group grants) and a
delegation action (giving the group's members new access). Both checks
must pass.

### Effective scope (`/opa/effective_scope/`)

| Operation | Who can do it |
|---|---|
| Read | Any authenticated user |

## Org admin and team admin

These are not special-cased in code. They are expressed as regular OPA
roles with specific policies.

**Org admin** (example for org 5): role with org-scoped policies for
all resources in org 5, including `opagroup.change.organization_id == 5`
to manage teams.

**Team admin** (example for group 7): role with
`opagroup.read.id == 7` and `opagroup.change.id == 7` to manage that
specific group's membership. To assign roles to the group, the team
admin also needs `change` on the resources covered by those roles.

**Team member**: not a role — a user is a team member by being in the
OPAGroup's `users` M2M. Their permissions come from whatever roles are
assigned to that group.
