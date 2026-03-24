# DAB OPA v1 Spec

## 1. Purpose

**DAB OPA** is an add-on Django app for **Django Ansible Base** projects that provides a constrained OPA-backed authorization system.

The host Django app will:

* add `dab_opa` to `INSTALLED_APPS`
* configure DAB OPA registry/settings
* use DAB OPA APIs/hooks when permission evaluation is needed

DAB OPA will:

* store roles and policies in Django models
* let administrators assign roles to OPA-specific groups
* resolve a user’s effective policies through group membership
* validate policies against registered Django model metadata from settings
* call OPA with effective policies
* return queryset-compatible filters/scopes

This system is intentionally **narrow and boring** in v1:

* no freeform Rego authoring
* no arbitrary ABAC
* no predicate trees
* no deny rules
* no object-bound role assignments
* only **atomic policies**
* all policies combine by **OR**

---

## 2. Core design principles

### 2.1 Django is the schema authority

The host app defines in settings:

* what resources exist
* what actions exist
* what policy fields are allowed
* what action dependencies exist

There are **no DB-backed `ResourceType` or `ResourceAction` models**.

### 2.2 Policies are atomic

A policy is one simple clause only, for example:

* `organization_id == 17`
* `created_by_id == current_user.id`
* `id == 123`

There is no boolean expression tree in v1.

### 2.3 Roles are collections of policies

A role is a named collection of policies.

### 2.4 Role assignment is group-based only

The assignment model is:

* `(dab_opa_group, role)`

Not `(user, role)`, and not `(principal, object, role)`.

Each user will have an auto-created single-user OPA group so that user-specific assignment is still representable through groups.

### 2.5 Effective access is OR

For a given `(resource, action)`:

* all matching policies across all effective roles are ORed together

### 2.6 Superuser bypass exists outside the ordinary policy model

`is_superuser` can do everything.

This may be implemented as a hard bypass rather than as ordinary policy evaluation.

### 2.7 OPA receives effective policies, not roles

Django resolves:

* user -> `dab_opa_groups`
* groups -> roles
* roles -> matching policies

Then Django sends **effective policies** to OPA.

OPA does **not** need to understand groups or role assignment.

---

## 3. Scope of v1

### Included

* OPA-specific groups
* group-role assignment
* roles
* atomic policies
* policy validation against settings registry
* effective policy resolution for a user
* OPA call using effective policies
* local Django reference evaluator for testing/debugging
* action dependency validation
* strict/loose role editing behavior

### Excluded

* arbitrary Rego editing
* arbitrary principal attributes
* policy trees / nested boolean expressions
* deny policies
* object-bound role assignment
* policy reuse across roles as a first-class optimization
* field-level write masking
* multi-object transactional policy compilation systems
* production fallback to local evaluator as the primary enforcement path

---

## 4. Naming and app conventions

### App/package

* package/app: `dab_opa`

### User relation

Avoid ordinary `User.groups`.

The M2M relationship between users and OPA groups is defined on the `OPAGroup` model side:

* `OPAGroup.users = ManyToManyField(settings.AUTH_USER_MODEL, ...)`

This avoids requiring host apps to modify their User model. Users can access their groups via the reverse relation (e.g., `user.opagroup_set` or a custom `related_name`).

### Group model naming

Recommended model name:

* `OPAGroup`

inside app `dab_opa`, so its full identity is clear.

If more legalistic naming is preferred, `DABOPAGroup` is also acceptable.

This spec uses `OPAGroup` for readability.

---

## 5. Data model

## 5.1 `OPAGroup`

OPA-specific group/team model.

### Fields

* `name`
* `organization` FK (to the model specified by `ANSIBLE_BASE_ORGANIZATION_MODEL`)
* `users` M2M to `settings.AUTH_USER_MODEL`
* standard created/modified metadata if desired
* optional system/managed flags if useful later

### Notes

* This is distinct from Django auth `Group`
* The user M2M is defined on `OPAGroup`, not on the User model, so host apps do not need to modify their User model
* One auto-created single-user `OPAGroup` should exist per user

---

## 5.2 User <-> OPAGroup membership

Defined on `OPAGroup`:

* `users = ManyToManyField(settings.AUTH_USER_MODEL, related_name='dab_opa_groups', ...)`

This relation is the only user-group membership used for DAB OPA resolution.

---

## 5.3 `Role`

Named collection of policies.

### Fields

* `name`
* `description`
* optional `managed` / `system` flag
* created/modified metadata

### Semantics

A role has no meaning by itself except through its attached policies.

---

## 5.4 `Policy`

Atomic permission clause attached to a role.

### Fields

* `role` FK to `Role`
* `resource` string
* `action` string
* `field_name` string
* `operator` string enum
* `value_type` string enum
* `constant_value` `TextField(null=True, blank=True)`
* optional `description`
* optional `position` / ordering field
* created/modified metadata

### v1 allowed operators

* `eq`

You previously allowed the possibility of `in`, but v1 should stay simplest unless a concrete use case appears. If desired, `in` can remain a future-ready internal enum value but should not be part of the primary v1 UI.

### v1 allowed `value_type`

* `constant`
* `principal_user_id`

### Semantics examples

A policy row may represent:

* `resource=project`, `action=read`, `field_name=organization_id`, `operator=eq`, `value_type=constant`, `constant_value="17"`
* `resource=project`, `action=read`, `field_name=created_by_id`, `operator=eq`, `value_type=principal_user_id`

### Important

A policy is always:

* exactly one resource
* exactly one action
* exactly one atomic condition

No grouped expressions.

---

## 5.5 `GroupRoleAssignment`

Assignment model linking groups to roles.

### Fields

* `group` FK to `OPAGroup`
* `role` FK to `Role`
* created/modified metadata if desired

### Unique constraint

* unique on `(group, role)`

### Semantics

This is the only role assignment mechanism in v1.

---

## 6. Registry/settings model

The host app defines all policy-manageable metadata in Django settings.

Recommended top-level setting name:

* `DAB_OPA`

## 6.1 Shape

```python
DAB_OPA = {
    "strict_mode_default": False,
    "shared_fields": {
        "id": {
            "django_path": "id",
            "type": "pk",
            "operators": ["eq"],
        },
        "organization_id": {
            "django_path": "organization_id",
            "type": "fk",
            "operators": ["eq"],
        },
        "created_by_id": {
            "django_path": "created_by_id",
            "type": "fk",
            "operators": ["eq"],
        },
    },
    "resources": {
        "project": {
            "model": "myapp.Project",
            "actions": ["read", "change", "delete"],
            "fields": {
                "status": {
                    "django_path": "status",
                    "type": "string",
                    "operators": ["eq"],
                },
            },
            "action_dependencies": {
                "change": ["read"],
                "delete": ["read"],
            },
        },
        "job": {
            "model": "myapp.Job",
            "actions": ["read", "start", "execute"],
            "fields": {},
            "action_dependencies": {
                "start": ["read"],
                "execute": ["read"],
            },
        },
    },
}
```

---

## 6.2 Shared fields

`shared_fields` are fields assumed or exposed across multiple resources.

Examples:

* `id`
* `organization_id`
* `created_by_id`

These are merged into each resource’s effective allowed fields.

---

## 6.3 Resource definition

Each resource defines:

* model import path
* valid actions
* resource-specific allowed fields
* action dependency rules

---

## 6.4 Allowed field naming

Each policy `field_name` must match a key in:

* resource-specific `fields`, or
* `shared_fields`

---

## 6.5 Validation source of truth

During policy validation, DAB OPA must use:

* the registry settings
* the actual Django model field metadata resolved from the configured model

This is how `constant_value` is coerced and validated.

---

## 7. Policy semantics

## 7.1 Allowed v1 policy shapes

### Object primary key ownership/specific object

* `id == <constant>`

### Organization-scoped access

* `organization_id == <constant>`

### Creator-owned access

* `created_by_id == current_user.id`

These are the main intended v1 use cases.

---

## 7.2 Policy combination

For a given `(resource, action)`:

* gather all policies from all effective roles
* OR them together

Example:

Role A contains:

* `project.read.organization_id == 17`

Role B contains:

* `project.read.created_by_id == principal_user_id`

Effective queryset filter becomes:

```python
Q(organization_id=17) | Q(created_by_id=request.user.id)
```

---

## 7.3 No matching policies

If no matching policies exist for a user for a given `(resource, action)`, the result is:

* allow nothing
* empty queryset scope

---

## 7.4 No negative logic

Not supported in v1:

* `not`
* deny
* precedence rules between allow and deny

---

## 8. Value handling

## 8.1 `constant_value`

`Policy.constant_value` is a `TextField`.

Reason:

* supports UUIDs and nontrivial serialized values better than a narrow string field
* avoids multiple typed columns
* validation/coercion still uses the actual target model field type

## 8.2 Validation/coercion

When saving a constant policy:

1. resolve the target model from resource settings
2. resolve the target Django field via configured field metadata
3. coerce `constant_value` into that field’s expected Python/domain form
4. reject invalid values with model/form/API validation errors

Examples:

* integer FK field -> must parse as integer
* UUID field -> must parse as valid UUID string
* string field -> allow string
* PK type -> validate according to actual model PK type

## 8.3 `principal_user_id`

For `value_type="principal_user_id"`, `constant_value` must be blank/null.

This is the only runtime principal reference allowed in v1.

---

## 9. Effective access resolution flow

For a user request involving `(resource, action)`:

1. if `user.is_superuser`, bypass and allow all
2. resolve effective policy IDs: traverse `User -> OPAGroups -> Roles -> Policies`, collect deduplicated list of policy PKs
3. send OPA request with `(user_id, is_superuser, resource, action, policy_ids)`
4. OPA looks up the referenced policies from its cached data (`data.dab_opa.policies[pk]`), filters by resource/action, resolves `value_type` (e.g. `principal_user_id`), and returns resolved clauses
5. receive resolved clauses from OPA
6. compile clauses into Django `Q(...)`
7. apply to queryset

Policy definitions are cached in OPA (pushed on Policy create/modify/delete). Per-request, Django resolves which policy IDs apply to the user and sends just the IDs.

---

## 10. OPA boundary

## 10.1 Rego is static, policy definitions are cached

The Rego policy loaded into OPA is a **static set of rules** that defines how to evaluate policies. It does not encode any user/group/role data.

Policy definitions are cached in OPA at `data.dab_opa.policies`, keyed by PK. They are pushed via `PUT /v1/data/dab_opa/policies` whenever a Policy is created, modified, or deleted.

Per-request, Django resolves the user's effective policy IDs by traversing `User -> OPAGroups -> Roles -> Policies` and sends them as `input.policy_ids`. OPA looks up the referenced policies from its cached data.

The Rego rules handle:

* `is_superuser` bypass
* policy lookup by PK from cached data
* resource/action filtering
* `principal_user_id` substitution (resolving the value type at eval time)
* OR combination of matching policies
* object attribute matching (tier 2)
* related object checks (tier 2)

---

## 10.2 OPA request format

Each request includes the user's effective policy IDs:

```json
{
  "input": {
    "principal": {
      "user_id": 42,
      "is_superuser": false
    },
    "target": {
      "resource": "project",
      "action": "read"
    },
    "policy_ids": [42, 43, 55]
  }
}
```

OPA looks up the referenced policies from its cached data, filters by resource/action, evaluates using its Rego rules, and returns the resolved scope.

---

## 10.3 OPA responsibilities

OPA should:

* evaluate the pre-loaded generated Rego policy
* honor `is_superuser` bypass
* substitute `principal_user_id` with actual `principal.user_id`
* combine all matching policies by OR
* return a normalized scope representation Django can convert to `Q(...)`

OPA should not:

* resolve groups or roles (Django does this before each request)
* introspect Django models
* make external calls

---

## 10.4 OPA response format

Suggested response — a flat list of resolved clauses:

```json
{
  "clauses": [
    {
      "field_name": "organization_id",
      "operator": "eq",
      "value": 17
    },
    {
      "field_name": "created_by_id",
      "operator": "eq",
      "value": 42
    }
  ]
}
```

Django ORs these clauses into a `Q(...)` expression.

## 10.5 Sync scope

Policy definitions are synced to OPA when a Policy is created, modified,
or deleted (via `post_save`/`post_delete` signals). This pushes all policy
definitions to `PUT /v1/data/dab_opa/policies`.

Group membership and role assignment changes do NOT require a sync --
those affect user-to-policy resolution, which happens per-request in Django.

The Rego rules are static and loaded once at OPA startup from the
bundled `policy.rego` file.

---

## 11. Local Django evaluator

DAB OPA should include a local evaluator that:

* takes effective policies
* resolves `principal_user_id`
* produces equivalent Django `Q(...)`

This exists for:

* unit tests
* integration tests
* debugging
* verifying OPA parity
* development tooling

It should not be the intended primary production enforcement path.

---

## 12. Queryset compilation rules

Given resolved atomic clauses, Django compiles each clause to a `Q(...)` and ORs them together.

### Example

Resolved clauses:

```python
[
    {"field_name": "organization_id", "operator": "eq", "value": 17},
    {"field_name": "created_by_id", "operator": "eq", "value": 42},
]
```

Compile to:

```python
Q(organization_id=17) | Q(created_by_id=42)
```

### Field resolution

Use registry metadata to map `field_name` to `django_path`.

So:

* `organization_id` -> `organization_id`
* later resource-specific names could map to different ORM lookup paths if needed

### No clauses

Compile to an always-false filter, e.g.:

* `.none()`
* or equivalent false `Q` strategy

---

## 13. Action dependencies

## 13.1 Why

Some actions should imply visibility requirements.

Examples:

* `change` usually requires `read`
* `delete` usually requires `read`
* `execute` may require `read`
* custom actions may also require `read`

## 13.2 Where configured

In settings, per resource:

```python
"action_dependencies": {
    "change": ["read"],
    "delete": ["read"],
    "execute": ["read"],
}
```

## 13.3 Enforcement mode

Validation should occur at role editing/construction time.

For each policy in a role:

* if it targets action `A`
* and `A` requires `read`
* the role must also contain at least one corresponding policy for required action(s)

“Corresponding” in v1 should mean:

* same `resource`
* same `field_name`
* same `operator`
* same value semantics

So if role contains:

* `project.change.organization_id == 17`

it must also contain:

* `project.read.organization_id == 17`

Likewise for:

* `project.change.created_by_id == principal_user_id`

must also contain:

* `project.read.created_by_id == principal_user_id`

This is intentionally dumb and explicit.

---

## 14. Strict vs loose role editing

## 14.1 Strict mode

When adding a policy whose action has dependencies, the system rejects the edit unless the corresponding required policy already exists or is included in the same request.

Return validation error / HTTP 400 in API.

## 14.2 Loose mode

When adding a dependent policy, the system auto-adds the corresponding required policy/policies.

### Example

Adding:

* `project.change.created_by_id == principal_user_id`

auto-adds:

* `project.read.created_by_id == principal_user_id`

## 14.3 Configuration

There should be:

* a global default from settings
* ability for the role editing endpoint/UI to choose strict or loose behavior explicitly

### Recommendation

* UI defaults to loose
* API supports explicit mode selection
* validation engine supports both

---

## 15. Admin/UI behavior

You wanted editing centered on the role page.

## 15.1 Role detail page

Role detail page should support:

* editing role metadata
* listing attached policies
* creating new policies for that role
* deleting policies
* seeing dependency consequences

## 15.2 Policy creation UI

Form-built only in v1.

User should choose:

* resource
* action
* field_name
* operator
* value_type
* constant_value if applicable

The form should dynamically filter valid choices using the registry settings.

## 15.3 Validation messages

Validation must clearly explain:

* invalid resource
* invalid action for resource
* invalid field for resource
* invalid operator for field
* invalid constant value for model field type
* missing dependency policies

## 15.4 Loose mode UX

If loose mode auto-adds required read policies, the UI should tell the admin exactly what was added.

---

## 16. API behavior

## 16.1 Policy creation/editing endpoints

Policies should be created/edited through role-centric endpoints or role detail operations.

That matches your desired workflow.

## 16.2 Mode parameter

Role/policy mutation APIs should accept a mode such as:

* `strict`
* `loose`

If omitted, use configured default.

---

## 17. Auto-created per-user OPA group

For every user, DAB OPA should create or ensure existence of a single-user `OPAGroup`.

Purpose:

* preserve group-only assignment model
* still allow effectively user-specific role assignment

### Behavior

On user creation or first-time sync:

* ensure a single-user OPA group exists
* ensure user belongs to it

Naming can be implementation-defined, but it should be clearly system-managed.

Example style:

* `user:<pk>`
* or another deterministic scheme

This group should likely be marked as managed/system-generated.

---

## 18. Organization model setting

DAB OPA requires a new setting to identify the host app's organization model:

```python
ANSIBLE_BASE_ORGANIZATION_MODEL = 'myapp.Organization'
```

This follows the same pattern as `ANSIBLE_BASE_TEAM_MODEL`. The `OPAGroup.organization` FK uses this setting to reference the correct model.

---

## 18.1 Group organization field

`OPAGroup.organization` exists in v1 because:

* groups are organization-scoped objects in your system worldview
* later permissions around groups themselves may rely on this
* admin management likely benefits from it

However, `group.organization` is **not** part of the v1 OPA request contract unless a future policy explicitly needs it.

In v1, group organization affects:

* group management
* role assignment administration
* future extensibility

Not runtime OPA input.

---

## 20. Testing strategy

There will be a lot of testing. The test plan should include:

## 20.1 Registry validation tests

* invalid resource rejected
* invalid action rejected
* invalid field rejected
* invalid operator rejected
* invalid constant_value rejected
* UUID coercion works
* FK/integer coercion works

## 20.2 Role dependency tests

* strict mode rejects missing required read policy
* loose mode auto-adds required read policy
* exact “corresponding policy” matching works

## 20.3 Effective policy resolution tests

* user gets policies through direct single-user OPA group
* user gets policies through additional shared OPA groups
* combined policies across roles are ORed
* duplicate equivalent policies do not break behavior

## 20.4 OPA contract tests

* Django -> OPA payload shape is correct
* OPA returns expected resolved clauses
* local evaluator matches OPA result

## 20.5 Queryset tests

* resolved clauses become correct `Q(...)`
* empty policy set yields empty queryset
* superuser bypass yields full queryset

---

## 21. Implementation phases

## Phase 1: skeleton and settings

* create `dab_opa` app
* define settings schema and registry loader
* define validation helpers for resource/action/field metadata

## Phase 2: models

* `OPAGroup`
* user M2M `dab_opa_groups`
* `Role`
* `Policy`
* `GroupRoleAssignment`

## Phase 3: policy validation

* validate policy rows against settings and actual model metadata
* validate `constant_value`
* implement action dependency checking

## Phase 4: role editing flow

* role detail editing UI/API
* strict/loose behavior
* auto-add dependency policies in loose mode

## Phase 5: effective policy resolution

* resolve user -> groups -> roles -> policies
* filter policies by resource/action

## Phase 6: local evaluator

* resolve `principal_user_id`
* convert policies into `Q(...)`

## Phase 7: OPA integration

* serialize effective policies to OPA payload
* consume OPA response
* compile to `Q(...)`
* add parity tests against local evaluator

## Phase 8: host app integration hooks

* queryset filtering helpers
* object permission helpers built on queryset scope
* optional view integration points

---

## 22. Recommended helper APIs

DAB OPA should expose Python helpers like:

* `get_effective_policies(user, resource, action)`
* `build_local_q(user, resource, action)`
* `build_opa_q(user, resource, action)`
* `filter_queryset_for_user(queryset, user, action)`
* `user_can_access_obj(user, obj, action)`
  implemented via queryset scoping, not special separate logic

The guiding rule remains:

**single-object evaluation is derived from queryset/scoping behavior, not the other way around.**

---

## 23. Future planning note

At the end of the implementation/design document, include a separate future-planning note stating that later generalization may explore:

* grouped predicates / boolean trees
* broader operator support
* reusable policy templates
* more principal references
* richer OPA-side explanation/debug output
* field-level write restrictions
* more advanced action dependency semantics

But explicitly note that these are **not committed for v1**, and it is currently unknown whether they will be worth the complexity.

---

## 24. Final v1 summary

DAB OPA v1 is a constrained OPA integration for Django Ansible Base where:

* the host app declares resources/actions/fields in settings
* users belong to `dab_opa`-specific groups
* groups get roles
* roles contain atomic policies
* policies are validated against real Django model fields
* Rego rules are static and loaded once at OPA startup
* policy definitions are cached in OPA (synced on Policy create/modify/delete)
* per-request OPA input includes (user, resource, action, policy_ids)
* OPA looks up referenced policies from cached data and returns resolved clause scopes
* Django turns those scopes into queryset filters
* all access is additive OR logic
* `is_superuser` bypasses everything
* dependency rules like `change -> read` are enforced during role construction/editing

This is intentionally limited, explicit, and compliance-friendly.
