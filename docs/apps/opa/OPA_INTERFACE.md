# DAB <-> OPA Interface

This document describes the HTTP interface between Django Ansible Base (DAB)
and the OPA sidecar.

## Architecture overview

OPA runs as a sidecar container on each node (port 8181). DAB communicates
with it over two interfaces:

1. **Data API** (`PUT /v1/data/dab_opa/policies`) -- DAB pushes policy
   definitions to OPA when policies are created, modified, or deleted.
   These are cached in OPA's in-memory store.

2. **Query API** (`POST /v1/data/dab_opa`) -- DAB sends authorization
   questions with the user's effective policy IDs. OPA looks up the
   referenced policies from its cached data and evaluates them.

```
+--------------+    PUT /v1/data/dab_opa/policies   +--------------+
|              |  ------------------------------>   |              |
|   Django     |    (policy definitions, on change) |     OPA      |
|   (DAB)      |                                    |  (sidecar)   |
|              |    POST /v1/data/dab_opa           |              |
|              |  <------------------------------->  |              |
|              |    (policy_ids per request)         |              |
+--------------+                                    +--------------+
```

## Policy sync: what DAB pushes

When a Policy model is created, modified, or deleted, a `post_save`/`post_delete`
signal triggers `sync_policies_to_opa()`. This pushes all policy definitions
to OPA via `PUT /v1/data/dab_opa/policies`, keyed by policy PK.

Each policy definition is a clause dict:

```json
{
  "42": {
    "resource": "inventory",
    "action": "read",
    "field_name": "organization_id",
    "operator": "eq",
    "value_type": "constant",
    "value": 4
  },
  "43": {
    "resource": "inventory",
    "action": "read",
    "field_name": "created_by_id",
    "operator": "eq",
    "value_type": "principal_user_id"
  }
}
```

Note: `constant` policies include a `value` field; `principal_user_id`
policies do not (the value is resolved at eval time from `input.principal.user_id`).

## Per-request policy resolution

Before each OPA query, DAB resolves the user's effective policy IDs by
traversing `User -> OPAGroup -> GroupRoleAssignment -> Role -> Policy`.
The result is a deduplicated list of policy PKs (integers).

This list is sent as `input.policy_ids` in every query. OPA uses these
IDs to look up the matching policy definitions from its cached data.

## Rego rules: what OPA does with queries

The Rego policy is loaded from [`ansible_base/opa/bundles/policy.rego`](https://github.com/AlanCoding/django-ansible-base/blob/dab_opa/ansible_base/opa/bundles/policy.rego).

### Policy lookup

OPA looks up each referenced policy by PK from `data.dab_opa.policies`:

```rego
some pid in input.policy_ids
p := data.dab_opa.policies[format_int(pid, 10)]
p.resource == input.target.resource
p.action == input.target.action
```

### Clause resolution

Every policy has a `value_type`. The Rego resolves it:

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
        some pid in input.policy_ids
        p := data.dab_opa.policies[format_int(pid, 10)]
        p.resource == input.target.resource
        p.action == input.target.action
        clause := _resolve_clause(p)
    ]
}

allow if { count(clauses) > 0 }
```

This iterates over the user's policy IDs, looks up each policy, filters
by resource/action, and returns resolved clauses. DAB compiles these into
Django `Q()` filters.

### Tier 2 rules (object evaluation)

```rego
object_allowed if {
    some pid in input.policy_ids
    p := data.dab_opa.policies[format_int(pid, 10)]
    p.resource == input.target.resource
    p.action == input.target.action
    clause := _resolve_clause(p)
    _clause_matches_object(clause)
}

_clause_matches_object(clause) if {
    clause.operator == "eq"
    input.object[clause.field_name] == clause.value
}
```

When `input.object` is present, OPA checks whether the object's actual
field values match any of the user's policies. This returns a concrete
boolean rather than filter clauses.

### Related object rules

```rego
related_denied contains field if {
    some field, check in input.related
    not _related_allowed(check)
}

_related_allowed(check) if {
    some pid in input.policy_ids
    p := data.dab_opa.policies[format_int(pid, 10)]
    p.resource == check.resource
    p.action == check.action
    clause := _resolve_clause(p)
    # ... matches by ID or org-scoped
}
```

When `input.related` is present, OPA checks whether the user has
permission on each related object. The same `input.policy_ids` are used --
OPA filters by each related entry's resource/action from the cached data.
Returns the set of field names where the check failed.

## Query types

All queries go to the same endpoint (`POST /v1/data/dab_opa`) and the
same Rego rules evaluate. The difference is what fields are present in
`input` -- this determines which rules fire.

### Tier 1: Queryset filtering

**Purpose:** "What objects of this type can this user access?"

DAB sends the principal, target, and the user's policy IDs. OPA looks up
the referenced policies, filters by resource/action, resolves value_types,
and returns clauses that DAB compiles into Django ORM filters.

**Request:**
```json
{
  "input": {
    "principal": {"user_id": 11, "is_superuser": false},
    "target": {"resource": "inventory", "action": "read"},
    "policy_ids": [42, 43, 55]
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

**When no permission exists** (empty policy_ids or no matching policies):
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
with the user's policy IDs. OPA looks up and evaluates the policies
against the concrete values and returns a boolean.

**Request** (user can change inventory 5 -- it's in org 4):
```json
{
  "input": {
    "principal": {"user_id": 11, "is_superuser": false},
    "target": {"resource": "inventory", "action": "change"},
    "object": {"id": 5, "organization_id": 4, "credential_id": 1, "created_by_id": null},
    "policy_ids": [42, 43]
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
    "policy_ids": [42, 43]
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
optionally its org_id. OPA checks each related entry independently
using the same `input.policy_ids`.

**Request** (user has `use` on credential 1 -- allowed):
```json
{
  "input": {
    "principal": {"user_id": 11, "is_superuser": false},
    "target": {"resource": "inventory", "action": "change"},
    "object": {"id": 5, "organization_id": 4, "credential_id": 1, "created_by_id": null},
    "policy_ids": [42, 43, 67],
    "related": {
      "credential": {
        "resource": "credential",
        "action": "use",
        "id": 1,
        "org_id": 4
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
    "policy_ids": [42, 43, 67],
    "related": {
      "credential": {
        "resource": "credential",
        "action": "use",
        "id": 2,
        "org_id": 4
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
| `OPARelatedAccessMixin.create()` | Tier 2 | Full OPA check with `related` entries at serializer layer |
| `OPARelatedAccessMixin.update()` | Tier 2 | Full OPA check with changed FK `related` entries at serializer layer |

The permission class (`OPAPermission`) and the serializer mixin
(`OPARelatedAccessMixin`) are separate layers. The permission class
handles coarse capability checks (DRF also calls it for OPTIONS/schema
generation with mock requests that have no data). The serializer mixin
handles fine-grained related object checks after the object is
constructed.

### PATCH/PUT flow and related object checks

On a PATCH or PUT request, the authorization flow involves two OPA calls:

1. **`OPAPermission.has_object_permission()`** sends a tier 2 OPA query
   with `object_allowed` only -- it does NOT send `input.related`. This
   checks whether the user can change the object itself (e.g., "do they
   have change permission on this inventory?"). If `object_allowed` is
   false, the request is denied (403 or 404).

2. **`OPARelatedAccessMixin.update()`** runs at the serializer layer
   **after** the object is saved (inside a transaction). It compares old
   vs new FK values, builds the `related` dict for changed FKs, and
   sends a **second tier 2 OPA query** with both the object and its
   related entries. OPA evaluates `object_allowed` (again, redundantly)
   and `related_denied` together. If `related_denied` comes back
   non-empty, the transaction is rolled back and a 403 is returned with
   the failing field names.

This intentional double-check ensures the full authorization decision
(object access + related object permissions) goes through OPA for
compliance. The same pattern applies to POST/create via
`OPARelatedAccessMixin.create()`.

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
