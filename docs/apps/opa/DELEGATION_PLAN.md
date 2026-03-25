# DAB OPA Delegation Plan

## Goal

Replace the superuser-only `IsSuperuser` permission class on OPA
management endpoints with a delegation model where any user who has
`change` access to a resource can delegate permissions on that resource
to other users.

## Core rule

**You can delegate access to any resource you have `change` on.**

If you have `change` on inventory 42, you can grant `read`, `change`,
or `delete` on inventory 42 to others. If you have org-scoped `change`
on inventories in org 5, you can grant any action on inventories in
org 5 (org-scoped or narrower).

You cannot delegate broader access than you hold.

---

## OPAGroup as an OPA-managed resource

OPAGroup is not currently registered in the OPA resource registry.
To support delegation, it must be, because:

- "Team admin" = has `change` on a specific OPAGroup
- "Org admin managing teams" = has org-scoped `change` on OPAGroups

### Registration

Add `opagroup` to the host app's `DAB_OPA` config:

```python
"opagroup": {
    "model": "dab_opa.OPAGroup",
    "actions": ["read", "change", "delete", "add"],
    "parent_field_name": "organization",
    "fields": {},
    "action_dependencies": {
        "change": ["read"],
        "delete": ["read"],
    },
},
```

This means:
- `opagroup.change.id == 7` → team admin for group 7
- `opagroup.change.organization_id == 5` → can manage all groups in org 5
- `opagroup.read.organization_id == 5` → can see all groups in org 5

### Self-referential bootstrapping

OPAGroup management is now gated by OPA policies about OPAGroups.
This creates a bootstrap question: how does the first org admin get
`change` on OPAGroups?

Answer: the superuser creates the initial org admin role with policies
covering OPAGroup management, then assigns it. After that, org admins
can delegate further. This is the same bootstrap pattern as any RBAC
system.

---

## Endpoint access rules

### Roles: open creation, scoped reads

| Operation | Who can do it |
|---|---|
| Create | Any authenticated user |
| List/Read | Any authenticated user (see note) |
| Update | Creator or superuser |
| Delete | Creator or superuser (if not managed) |

Roles are inert containers. Creating a role grants nothing — it's
the policies inside and the assignment to a group that matter. The
gates are on policy creation and role assignment.

**Note on read scoping:** In v1, keep roles globally readable. They
contain no sensitive information (just a name and description). Policy
details are also not sensitive — they describe access rules, not data.

### Policies: gated by `change` on the resource

| Operation | Who can do it |
|---|---|
| Create | User has `change` covering the policy's scope (see validation below) |
| List/Read | Any authenticated user |
| Delete | User has `change` covering the policy's scope, or superuser |
| Update | Not allowed (immutable — delete and recreate) |

**Why immutable?** A policy is shared across all groups assigned its
role. Editing a policy silently changes access for every user who holds
that role. Delete-and-recreate is explicit and auditable.

#### Policy creation validation

When a user creates a policy `(resource, action, field_name, value)`,
validate that the user's existing `change` access covers the scope of
the new policy.

**For `field_name=id, value=X`** (object-scoped):

The user must have `change` on the specific object. Check:
```python
obj = resource_model.objects.get(pk=X)
user_can_access_obj(user, obj, "change")
```

**For `field_name=organization_id, value=X`** (org-scoped):

The user must have org-scoped `change` on that resource in org X.
An id-scoped `change` on one object in org X is NOT sufficient — that
would let someone with access to one inventory grant access to all
inventories in the org.

Check: the user has a `change` policy with
`field_name=organization_id, value=X` (or broader) for that resource.
```python
user_policies = get_effective_policies(user, resource, "change")
has_org_scope = any(
    c["field_name"] == "organization_id" and c["value"] == org_id
    for c in user_policies
)
```

**For `value_type=principal_user_id`**:

This policy grants "access to objects where field matches the holder's
user ID." This is a special self-scoping policy. The creating user
doesn't need to "have" this in the same way — they're granting a
pattern, not a specific scope.

Restrict to superusers in v1. These policies are typically created
during system setup (e.g., "creators can read their own objects") and
don't fit the delegation model.

### Groups: gated by `change` on the OPAGroup

| Operation | Who can do it |
|---|---|
| Create | User has `add` on `opagroup` in the target org |
| List/Read | User has `read` on `opagroup` (scoped) |
| Update | User has `change` on the group |
| Delete | User has `change` on the group (if not managed) |
| Add user | User has `change` on the group |
| Remove user | User has `change` on the group |

This is standard OPA-managed resource access — the OPAGroup viewset
uses `OPAPermission` + `OPAQuerySetMixin` like any other resource.

#### Group membership constraints

Adding a user to a group is gated by `change` on the group. No
additional check on the target user is needed in v1 — if you can
manage the group, you can add anyone to it. This matches the
simplicity of the system.

Future consideration: restrict to users in the same org as the group.

### Assignments: gated by group management + delegation check

| Operation | Who can do it |
|---|---|
| Create | User has `change` on the group AND `change` covering all policies in the role |
| List/Read | Any authenticated user |
| Delete | User has `change` on the group |

**Why check both?** Assigning a role to a group is simultaneously:
1. A group management action (you're changing what the group grants)
2. A delegation action (you're giving the group's members new access)

The user must be authorized for both.

#### Assignment creation validation

```python
# 1. Can the user manage this group?
user_can_access_obj(user, group, "change")

# 2. Does the user hold change access covering every policy in the role?
for policy in role.policies.all():
    validate_user_can_delegate_policy(user, policy)
```

`validate_user_can_delegate_policy` is the same check used for policy
creation (see above).

---

## Org admin and team admin as roles

These are not special-cased in code. They are expressed as regular
OPA roles with specific policies.

### Org admin role (example for org 5)

Policies:
```
organization.read.id == 5
organization.change.id == 5
organization.delete.id == 5
inventory.read.organization_id == 5
inventory.change.organization_id == 5
inventory.delete.organization_id == 5
inventory.add.organization_id == 5
opagroup.read.organization_id == 5
opagroup.change.organization_id == 5
opagroup.delete.organization_id == 5
opagroup.add.organization_id == 5
credential.read.organization_id == 5
credential.change.organization_id == 5
...
```

The org admin can:
- Manage all resources in org 5 (via org-scoped policies)
- Manage all groups in org 5 (via opagroup policies)
- Delegate access to any resource in org 5 (they have `change`)
- Create sub-roles and assign them to groups

### Team admin role (example for group 7)

Policies:
```
opagroup.read.id == 7
opagroup.change.id == 7
```

The team admin can:
- View and manage group 7's membership
- Assign roles to group 7 (if they also hold `change` on the
  resources covered by those roles)

A team admin who only has `change` on the group but no resource
policies can manage membership but cannot assign new roles (because
they can't pass the delegation check).

### Team member

Not a role in the access-control sense. A user is a "team member"
by being in the OPAGroup's `users` M2M. Their permissions come from
whatever roles are assigned to that group.

---

## Implementation plan

### Phase 1: Register OPAGroup as OPA resource

1. Add `opagroup` to `DAB_OPA` config (host app responsibility;
   add to test_app for testing)
2. Switch `OPAGroupViewSet` from `IsSuperuser` to
   `OPAPermission` + `OPAQuerySetMixin`
3. Add OPA-based filtering to group list (users only see groups they
   have `read` on)
4. Test: superuser can still CRUD groups; unpermissioned user cannot

### Phase 2: Delegation validation helpers

1. Add `validate_user_can_delegate_policy(user, policy)` — checks
   that user has `change` covering the policy's scope
2. Add `validate_user_can_delegate_role(user, role)` — checks all
   policies in the role
3. Handle the three scope types: object-scoped (`id`), org-scoped
   (`organization_id`), and `principal_user_id` (superuser-only)
4. Test: user with org-scoped change can create org-scoped and
   object-scoped policies; user with object-scoped change can only
   create object-scoped policies

### Phase 3: Policy endpoint delegation

1. Replace `IsSuperuser` on `PolicyViewSet` with delegation check
2. On create: validate the user can delegate the policy being created
3. On delete: validate the user can delegate the policy (same check)
4. Make policies immutable (remove update/partial_update)
5. Test: user can create policies within their scope; cannot exceed it

### Phase 4: Role endpoint — open creation

1. Replace `IsSuperuser` on `RoleViewSet` with authenticated-only
   for create, plus creator/superuser checks for update/delete
2. Add `created_by` field to Role model (nullable, for migration)
3. Test: any user can create roles; only creator can update/delete

### Phase 5: Assignment endpoint — dual gate

1. Replace `IsSuperuser` on `GroupRoleAssignmentViewSet`
2. On create: check `change` on group + delegation check on all
   policies in the role
3. On delete: check `change` on group
4. Test: user who manages group and holds relevant change can
   assign; user who manages group but lacks change cannot

### Phase 6: Group membership actions

1. `add_user` and `remove_user` actions already require `change`
   on the group (via `OPAPermission` on the viewset after Phase 1)
2. Verify this works end-to-end
3. Test: team admin can add/remove users; non-admin cannot

---

## End-to-end example

**Setup:** Superuser bootstraps org admin for org 5.

1. Superuser creates role "Org 5 Admin" with org-scoped policies for
   all resources + opagroup in org 5.
2. Superuser assigns "Org 5 Admin" to User A's per-user group.

**User A (org admin) creates a team:**

3. User A creates OPAGroup "DevOps" in org 5.
   (Allowed: User A has `opagroup.add.organization_id == 5`.)
4. User A adds User B and User C to "DevOps".
   (Allowed: User A has `opagroup.change.organization_id == 5`.)

**User A delegates inventory access to the team:**

5. User A creates role "Org 5 Inventory Reader".
6. User A creates policy `inventory.read.organization_id == 5`.
   (Allowed: User A has `inventory.change.organization_id == 5`.)
7. User A assigns "Org 5 Inventory Reader" to group "DevOps".
   (Allowed: User A has `change` on the group + `change` covering
   the role's policies.)
8. User B and C can now read all inventories in org 5.

**User A makes User B a team admin:**

9. User A creates role "DevOps Admin".
10. User A creates policy `opagroup.read.id == <DevOps pk>`.
11. User A creates policy `opagroup.change.id == <DevOps pk>`.
    (Allowed: User A has `opagroup.change.organization_id == 5`.)
12. User A assigns "DevOps Admin" to User B's per-user group.

**User B (team admin) manages the team:**

13. User B adds User D to "DevOps".
    (Allowed: User B has `opagroup.change.id == <DevOps pk>`.)
14. User D inherits the "Org 5 Inventory Reader" role through group
    membership.

**User B delegates specific inventory access:**

15. User B creates role "Prod Inventory Editor".
16. User B creates policy `inventory.change.id == <prod-inv pk>`.
    (Allowed? Only if User B has `inventory.change` on that
    inventory. User B has `inventory.read` org-scoped, but NOT
    `inventory.change`. So this is DENIED.)
17. User B would need `inventory.change` access to delegate change
    permission. The org admin can grant this if appropriate.

---

## Open questions resolved

1. **`principal_user_id` policies** — superuser-only in v1.

2. **Delegation gate** — `change` is the minimum. You can delegate
   any action on a resource you have `change` on, including actions
   you don't explicitly hold (e.g., `delete`). Rationale: `change`
   represents administrative control. If you can modify a resource,
   you can decide who else accesses it.

3. **Group membership** — gated by `change` on the group. No
   additional user-level check in v1.

4. **Policy immutability** — yes, policies are immutable. Delete
   and recreate. This prevents silent scope changes affecting all
   holders of a role.
