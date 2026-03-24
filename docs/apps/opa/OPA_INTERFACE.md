# DAB ↔ OPA Interface

This document describes the HTTP interface between Django Ansible Base (DAB)
and the OPA sidecar. All examples use real request/response data captured
from a running system.

## Architecture overview

OPA runs as a sidecar container on each node (port 8181). DAB communicates
with it over two interfaces:

1. **Data API** (`PUT /v1/data/...`) — DAB pushes pre-flattened policy data
   to OPA. This is a write-only sync operation.
2. **Query API** (`POST /v1/data/dab_opa`) — DAB sends authorization
   questions and OPA evaluates them against the stored policy data + Rego
   rules.

```
┌─────────────┐         PUT /v1/data          ┌─────────────┐
│             │  ──────────────────────────▶ │             │
│   Django    │                               │     OPA     │
│   (DAB)     │  POST /v1/data/dab_opa        │  (sidecar)  │
│             │  ◀────────────────────────▶ │             │
└─────────────┘                               └─────────────┘
```

## Policy data: what OPA knows

OPA does **not** store policies by name or reference them symbolically.
Instead, DAB pre-computes a flat lookup table of every user's effective
policies and pushes the entire table to OPA as a JSON document. OPA treats
this as in-memory data — the Rego rules simply index into it.

### The sync process

When `sync_to_opa()` runs, DAB:

1. Traverses `User → OPAGroup → GroupRoleAssignment → Role → Policy`
2. Builds a nested dict: `user_id → resource → action → [clauses]`
3. Pushes it to OPA via `PUT /v1/data/dab_opa/user_policies`

**Real sync payload** (user 11 has inventory read/change in org 4 and
use on credential 1):

```
PUT /v1/data/dab_opa/user_policies  →  204 No Content  (4ms)
```
```json
{
  "11": {
    "credential": {
      "use": [
        {"field_name": "id", "operator": "eq", "value_type": "constant", "value": 1}
      ]
    },
    "inventory": {
      "change": [
        {"field_name": "organization_id", "operator": "eq", "value_type": "constant", "value": 4}
      ],
      "read": [
        {"field_name": "organization_id", "operator": "eq", "value_type": "constant", "value": 4}
      ]
    }
  }
}
```

Each clause is an atomic condition: a field name, an operator, and a value.
OPA's Rego rules resolve these into either queryset filters (tier 1) or
object match checks (tier 2).

### Sync frequency and caching

The policy data lives in OPA's memory until overwritten by the next PUT.
There is no TTL, no cache invalidation, no polling. OPA serves queries
against whatever data was last pushed.

This means:
- Policy data is stale between syncs
- A sync replaces the entire dataset atomically (no partial updates)
- DAB is the single source of truth; OPA is a read-only evaluator

In the current design, `sync_to_opa()` is called after policy changes
(role/group/assignment modifications).

### Could we avoid per-request OPA calls?

Yes — and the system is designed to make this possible. Because the policy
data is a simple JSON lookup table, DAB includes a **local evaluator**
(`ansible_base.opa.evaluator`) that performs identical evaluation purely
in Django, without any OPA HTTP call. It traverses the same
`User → Group → Role → Policy` chain and applies the same clause logic.

The local evaluator exists today and all tier 1/tier 2 tests run against
both the OPA path and the local path. A future deployment could use the
local evaluator for all authorization and reserve OPA for audit logging
or advanced Rego rules (DENY policies, ABAC conditions) that can't be
expressed as simple clause lookups.

## How OPA resolves a user's policies

When a query arrives with `user_id: 11`, OPA does not fetch policies from
a database or call back to Django. The user's policies are already in
memory — they were pushed during the last sync as
`data.dab_opa.user_policies["11"]`.

The Rego rule that connects the query to the synced data is a direct key
lookup:

```rego
user_id := format_int(input.principal.user_id, 10)
policies := data.dab_opa.user_policies[user_id][input.target.resource][input.target.action]
```

This indexes three levels deep: `user_policies["11"]["inventory"]["read"]`
→ returns the list of clauses for that user/resource/action combination.
If any level is missing (user has no policies, or no policies for that
resource/action), `policies` is undefined and the rule doesn't fire —
resulting in `allow: false`.

Using the sync payload from the earlier example, a query for user 11
reading inventories resolves to:

```
data.dab_opa.user_policies["11"]["inventory"]["read"]
→ [{"field_name": "organization_id", "operator": "eq", "value_type": "constant", "value": 4}]
```

A query for user 11 deleting inventories resolves to:

```
data.dab_opa.user_policies["11"]["inventory"]["delete"]
→ (undefined — no delete policies exist for this user)
```

## Rego rules: what OPA does with queries

The Rego policy is loaded from [`ansible_base/opa/bundles/policy.rego`](https://github.com/AlanCoding/django-ansible-base/blob/dab_opa/ansible_base/opa/bundles/policy.rego). It
defines rules that OPA evaluates against `input` (from the query) and
`data` (from the sync). The full Rego is short — here are the key rules:

### Clause resolution

Every clause in the policy data has a `value_type`. The Rego resolves it:

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

The `principal_user_id` type enables creator-owns-object patterns: a
single policy like `field_name=created_by_id, value_type=principal_user_id`
means "users can access objects they created" — without storing a separate
clause per user.

### Tier 1 rules (queryset filtering)

```rego
clauses := resolved if {
    user_id := format_int(input.principal.user_id, 10)
    policies := data.dab_opa.user_policies[user_id][input.target.resource][input.target.action]
    resolved := [clause |
        some p in policies
        clause := _resolve_clause(p)
    ]
}

allow if { count(clauses) > 0 }
```

This looks up the user's policies for the requested resource/action and
returns them as resolved clauses. DAB compiles these into Django `Q()`
filters.

### Tier 2 rules (object evaluation)

```rego
object_allowed if {
    user_id := format_int(input.principal.user_id, 10)
    policies := data.dab_opa.user_policies[user_id][input.target.resource][input.target.action]
    some p in policies
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
    # ... checks user policies for check.resource/check.action
    # ... matches by ID or org-scoped
}
```

When `input.related` is present, OPA checks whether the user has
permission on each related object (e.g., `use` on a credential). Returns
the set of field names where the check failed.

## Query types

All queries go to the same endpoint (`POST /v1/data/dab_opa`) and the
same Rego rules evaluate. The difference is what fields are present in
`input` — this determines which rules fire.

### Tier 1: Queryset filtering

**Purpose:** "What objects of this type can this user access?"

DAB sends just the principal and target. OPA returns clauses that DAB
compiles into Django ORM filters.

**Request:**
```json
{
  "input": {
    "principal": {"user_id": 11, "is_superuser": false},
    "target": {"resource": "inventory", "action": "read"}
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
The `allow` field is a convenience — it's `true` when `clauses` is
non-empty.

**When no permission exists** (e.g., user has no `delete` policy):
```json
{
  "result": {
    "allow": false,
    "clauses": []
  }
}
```

DAB compiles empty clauses into `Q(pk__in=[])` — matching nothing.

### Tier 2: Object evaluation

**Purpose:** "Can this user perform this action on this specific object?"

DAB sends the object's registered field values in `input.object`. OPA
evaluates the user's clauses against the concrete values and returns a
boolean.

**Request** (user can change inventory 5 — it's in org 4):
```json
{
  "input": {
    "principal": {"user_id": 11, "is_superuser": false},
    "target": {"resource": "inventory", "action": "change"},
    "object": {"id": 5, "organization_id": 4, "credential_id": 1, "created_by_id": null}
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

The user has `change` on `inventory` scoped to `organization_id=4`. The
object's `organization_id` is `4` — match. `object_allowed` is `true`.

**Denied** (inventory 6 is in org 5, user only has scope for org 4):
```json
{
  "input": {
    "principal": {"user_id": 11, "is_superuser": false},
    "target": {"resource": "inventory", "action": "change"},
    "object": {"id": 6, "organization_id": 5, "credential_id": null, "created_by_id": null}
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
`related` specifies a resource, action, and the related object's ID. OPA
checks the user's policies for each related object independently.

**Request** (user has `use` on credential 1 — allowed):
```json
{
  "input": {
    "principal": {"user_id": 11, "is_superuser": false},
    "target": {"resource": "inventory", "action": "change"},
    "object": {"id": 5, "organization_id": 4, "credential_id": 1, "created_by_id": null},
    "related": {
      "credential": {"resource": "credential", "action": "use", "id": 1}
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

**Request** (user does NOT have `use` on credential 2 — denied):
```json
{
  "input": {
    "principal": {"user_id": 11, "is_superuser": false},
    "target": {"resource": "inventory", "action": "change"},
    "object": {"id": 5, "organization_id": 4, "credential_id": 2, "created_by_id": null},
    "related": {
      "credential": {"resource": "credential", "action": "use", "id": 2}
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
related credential check failed — user has `use` on credential 1 only,
not credential 2.

## How DAB uses each tier

| DRF lifecycle stage | Tier | What it checks |
|---|---|---|
| `has_permission()` (view-level, pre-object) | Tier 1 | "Does user have any add scope?" — `clauses` non-empty |
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

This captures sync pushes (PUT), tier 1 queries, and tier 2 evaluations.
Useful for debugging policy evaluation and understanding the authorization
flow.

## Response fields reference

Every query to `POST /v1/data/dab_opa` returns all evaluated rules. DAB
reads only the fields relevant to the tier:

| Field | Tier 1 | Tier 2 | Description |
|---|---|---|---|
| `allow` | ✓ | — | `true` if any clauses exist |
| `clauses` | ✓ | — | List of resolved clause dicts for queryset filtering |
| `object_allowed` | — | ✓ | `true` if object attributes match a clause |
| `related_denied` | — | ✓ | Set of field names where related checks failed |

The `user_policies` field also appears in the response (OPA returns the
full data document). DAB ignores it — it's the same data that was pushed
during sync and is useful only for debugging.
