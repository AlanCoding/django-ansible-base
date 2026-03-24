# DAB <-> OPA Interface

This document describes the HTTP interface between Django Ansible Base (DAB)
and the OPA sidecar.

## Architecture overview

OPA runs as a sidecar container on each node (port 8181). DAB communicates
with it over a single interface:

**Query API** (`POST /v1/data/dab_opa`) -- DAB sends authorization
questions with the user's effective policies included in each request.
OPA evaluates them against the Rego rules and returns the result.

```
+--------------+    POST /v1/data/dab_opa     +--------------+
|              |  <-------------------------> |              |
|   Django     |   (policies in each request) |     OPA      |
|   (DAB)      |                              |  (sidecar)   |
|              |                              |              |
+--------------+                              +--------------+
```

OPA is stateless -- it stores no policy data. DAB resolves the user's
effective policies at request time and sends them as `input.policies`.

## Policy resolution: what DAB sends

Before each OPA query, DAB resolves the user's effective policies by
traversing `User -> OPAGroup -> GroupRoleAssignment -> Role -> Policy`.
The result is a deduplicated list of clause dicts for the specific
resource/action being checked.

Each clause is an atomic condition with a field name, operator, value type,
and (for constants) a value:

```json
[
  {"field_name": "organization_id", "operator": "eq", "value_type": "constant", "value": 4},
  {"field_name": "created_by_id", "operator": "eq", "value_type": "principal_user_id"}
]
```

The `value_type` tells OPA how to resolve the value:
- `constant` -- use `value` as-is
- `principal_user_id` -- substitute the requesting user's ID at eval time

## Rego rules: what OPA does with queries

The Rego policy is loaded from [`ansible_base/opa/bundles/policy.rego`](https://github.com/AlanCoding/django-ansible-base/blob/dab_opa/ansible_base/opa/bundles/policy.rego).
It defines rules that OPA evaluates against `input` (from the query).
The full Rego is short -- here are the key rules:

### Clause resolution

Every clause has a `value_type`. The Rego resolves it:

```rego
# Constant values pass through as-is
_resolve_clause(p) := {"field_name": p.field_name, "operator": p.operator, "value": p.value} if {
    p.value_type == "constant"
}

# principal_user_id substitutes the requesting user's ID at query time
_resolve_clause(p) := {"field_name": p.field_name, "operator": p.operator, "value": input.principal.user_id} if {
    p.value_type == "principal_user_id"
}
```

### Tier 1 rules (queryset filtering)

```rego
clauses := resolved if {
    resolved := [clause |
        some p in input.policies
        clause := _resolve_clause(p)
    ]
}

allow if { count(clauses) > 0 }
```

This iterates over the policies sent in the request and returns them as
resolved clauses. DAB compiles these into Django `Q()` filters.

### Tier 2 rules (object evaluation)

```rego
object_allowed if {
    some p in input.policies
    clause := _resolve_clause(p)
    _clause_matches_object(clause)
}

_clause_matches_object(clause) if {
    clause.operator == "eq"
    input.object[clause.field_name] == clause.value
}
```

When `input.object` is present, OPA checks whether the object's actual
field values match any of the user's clauses. This returns a concrete
boolean rather than filter clauses.

### Related object rules

```rego
related_denied contains field if {
    some field, check in input.related
    not _related_allowed(check)
}

_related_allowed(check) if {
    some p in check.policies
    clause := _resolve_clause(p)
    # ... matches by ID or org-scoped
}
```

When `input.related` is present, OPA checks whether the user has
permission on each related object. Each related entry includes its own
`policies` list (resolved by DAB for that related resource/action).
Returns the set of field names where the check failed.

## Query types

All queries go to the same endpoint (`POST /v1/data/dab_opa`) and the
same Rego rules evaluate. The difference is what fields are present in
`input` -- this determines which rules fire.

### Tier 1: Queryset filtering

**Purpose:** "What objects of this type can this user access?"

DAB sends the principal, target, and the user's policies for that
resource/action. OPA resolves value_types and returns clauses that DAB
compiles into Django ORM filters.

**Request:**
```json
{
  "input": {
    "principal": {"user_id": 11, "is_superuser": false},
    "target": {"resource": "inventory", "action": "read"},
    "policies": [
      {"field_name": "organization_id", "operator": "eq", "value_type": "constant", "value": 4}
    ]
  }
}
```

**Response** (relevant fields):
```json
{
  "result": {
    "allow": true,
    "clauses": [
      {"field_name": "organization_id", "operator": "eq", "value": 4}
    ]
  }
}
```

**What DAB does with this:** Compiles `clauses` into
`Q(organization_id=4)` and filters `Inventory.objects.filter(Q(...))`.

**When no permission exists** (empty policies list):
```json
{
  "result": {
    "allow": false,
    "clauses": []
  }
}
```

DAB compiles empty clauses into `Q(pk__in=[])` -- matching nothing.

### Tier 2: Object evaluation

**Purpose:** "Can this user perform this action on this specific object?"

DAB sends the object's registered field values in `input.object` along
with the user's policies. OPA evaluates the clauses against the concrete
values and returns a boolean.

**Request** (user can change inventory 5 -- it's in org 4):
```json
{
  "input": {
    "principal": {"user_id": 11, "is_superuser": false},
    "target": {"resource": "inventory", "action": "change"},
    "object": {"id": 5, "organization_id": 4, "credential_id": 1, "created_by_id": null},
    "policies": [
      {"field_name": "organization_id", "operator": "eq", "value_type": "constant", "value": 4}
    ]
  }
}
```

**Response:**
```json
{
  "result": {
    "object_allowed": true,
    "related_denied": []
  }
}
```

**Denied** (inventory 6 is in org 5, user only has scope for org 4):
```json
{
  "input": {
    "principal": {"user_id": 11, "is_superuser": false},
    "target": {"resource": "inventory", "action": "change"},
    "object": {"id": 6, "organization_id": 5, "credential_id": null, "created_by_id": null},
    "policies": [
      {"field_name": "organization_id", "operator": "eq", "value_type": "constant", "value": 4}
    ]
  }
}
```
```json
{
  "result": {
    "object_allowed": false,
    "related_denied": []
  }
}
```

### Tier 2 with related object checks

**Purpose:** "Can this user change this object AND do they have permission
on the related objects being set?"

DAB sends `input.related` alongside `input.object`. Each entry in
`related` specifies a resource, action, the related object's ID, and
the user's policies for that related resource/action. OPA checks each
related entry independently.

**Request** (user has `use` on credential 1 -- allowed):
```json
{
  "input": {
    "principal": {"user_id": 11, "is_superuser": false},
    "target": {"resource": "inventory", "action": "change"},
    "object": {"id": 5, "organization_id": 4, "credential_id": 1, "created_by_id": null},
    "policies": [
      {"field_name": "organization_id", "operator": "eq", "value_type": "constant", "value": 4}
    ],
    "related": {
      "credential": {
        "resource": "credential",
        "action": "use",
        "id": 1,
        "policies": [
          {"field_name": "id", "operator": "eq", "value_type": "constant", "value": 1}
        ]
      }
    }
  }
}
```

**Response:**
```json
{
  "result": {
    "object_allowed": true,
    "related_denied": []
  }
}
```

**Request** (user does NOT have `use` on credential 2 -- denied):
```json
{
  "input": {
    "principal": {"user_id": 11, "is_superuser": false},
    "target": {"resource": "inventory", "action": "change"},
    "object": {"id": 5, "organization_id": 4, "credential_id": 2, "created_by_id": null},
    "policies": [
      {"field_name": "organization_id", "operator": "eq", "value_type": "constant", "value": 4}
    ],
    "related": {
      "credential": {
        "resource": "credential",
        "action": "use",
        "id": 2,
        "policies": [
          {"field_name": "id", "operator": "eq", "value_type": "constant", "value": 1}
        ]
      }
    }
  }
}
```

**Response:**
```json
{
  "result": {
    "object_allowed": true,
    "related_denied": ["credential"]
  }
}
```

The object itself is allowed (`organization_id=4` matches), but the
related credential check failed -- user has `use` on credential 1 only,
not credential 2.

## How DAB uses each tier

| DRF lifecycle stage | Tier | What it checks |
|---|---|---|
| `has_permission()` (view-level, pre-object) | Tier 1 | "Does user have any add scope?" -- `clauses` non-empty |
| `filter_queryset()` (list view) | Tier 1 | Compiles `clauses` into `Q()` filters |
| `has_object_permission()` (detail view) | Tier 2 | `object_allowed` on the specific instance |
| `OPARelatedAccessMixin.create()` | Local | Checks related FK permissions at serializer layer |
| `OPARelatedAccessMixin.update()` | Local | Checks changed FK permissions at serializer layer |

The permission class (`OPAPermission`) and the serializer mixin
(`OPARelatedAccessMixin`) are separate layers. The permission class
handles coarse capability checks (DRF also calls it for OPTIONS/schema
generation with mock requests that have no data). The serializer mixin
handles fine-grained related object checks after the object is
constructed.

## Could we avoid per-request OPA calls?

Yes -- and the system is designed to make this possible. Because the
policies are simple clause dicts, DAB includes a **local evaluator**
(`ansible_base.opa.evaluator`) that performs identical evaluation purely
in Django, without any OPA HTTP call. It traverses the same
`User -> Group -> Role -> Policy` chain and applies the same clause logic.

The local evaluator exists today and all tier 1/tier 2 tests run against
both the OPA path and the local path. A future deployment could use the
local evaluator for all authorization and reserve OPA for audit logging
or advanced Rego rules (DENY policies, ABAC conditions) that can't be
expressed as simple clause lookups.

## Request/response logging

Set the `DAB_OPA_LOG_FILE` environment variable to a file path to enable
request/response logging for all OPA interactions. Each entry is a JSON
object:

```json
{
  "timestamp": "2026-03-24T17:29:23+0000",
  "method": "POST",
  "url": "http://localhost:8181/v1/data/dab_opa",
  "request": { "input": { "..." } },
  "response": { "result": { "..." } },
  "status_code": 200,
  "duration_ms": 1.81
}
```

## Response fields reference

Every query to `POST /v1/data/dab_opa` returns all evaluated rules. DAB
reads only the fields relevant to the tier:

| Field | Tier 1 | Tier 2 | Description |
|---|---|---|---|
| `allow` | yes | -- | `true` if any clauses exist |
| `clauses` | yes | -- | List of resolved clause dicts for queryset filtering |
| `object_allowed` | -- | yes | `true` if object attributes match a clause |
| `related_denied` | -- | yes | Set of field names where related checks failed |
