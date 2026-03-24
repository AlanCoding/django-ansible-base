# OPA Policy Examples

This document shows the concrete data structures and OPA interactions for
several user personas created by `create_demo_data` and `migrate_rbac_to_opa`.
Use this as a reference for understanding how RBAC permissions translate into
OPA policy data, and how OPA evaluates access requests.

> **Prerequisites:** Run the setup steps from [DEMO.md](DEMO.md) sections 1-3
> before trying any of the commands below.

---

## How policy data works

After running `migrate_rbac_to_opa --sync`, OPA holds a data structure at
`/v1/data/dab_opa/user_policies` that maps each user ID to their permitted
resources, actions, and filter clauses. The structure looks like:

```json
{
  "<user_id>": {
    "<resource>": {
      "<action>": [
        {
          "field_name": "<field>",
          "operator": "eq",
          "value": "<pk>",
          "value_type": "constant"
        }
      ]
    }
  }
}
```

When Django asks OPA "can user X read inventories?", OPA looks up
`user_policies[X]["inventory"]["read"]` and returns the matching clauses.
Django then compiles those clauses into `Q()` objects and filters the queryset.

---

## Persona 1: org_admin (Organization Admin)

The `org_admin` user has the built-in Organization Admin role on the
AWX_community organization. This grants full access to all resources scoped to
that org.

### Policy data in OPA

```bash
curl -s http://localhost:8181/v1/data/dab_opa/user_policies | \
  jq '.result["6"]'
```

```json
{
  "inventory": {
    "read": [
      { "field_name": "organization_id", "operator": "eq", "value": 1, "value_type": "constant" }
    ],
    "change": [
      { "field_name": "organization_id", "operator": "eq", "value": 1, "value_type": "constant" }
    ],
    "delete": [
      { "field_name": "organization_id", "operator": "eq", "value": 1, "value_type": "constant" }
    ]
  },
  "organization": {
    "read": [
      { "field_name": "id", "operator": "eq", "value": 1, "value_type": "constant" }
    ],
    "change": [
      { "field_name": "id", "operator": "eq", "value": 1, "value_type": "constant" }
    ]
  },
  "team": {
    "read": [
      { "field_name": "organization_id", "operator": "eq", "value": 1, "value_type": "constant" }
    ],
    "change": [
      { "field_name": "organization_id", "operator": "eq", "value": 1, "value_type": "constant" }
    ],
    "delete": [
      { "field_name": "organization_id", "operator": "eq", "value": 1, "value_type": "constant" }
    ]
  }
}
```

**What this means:** org_admin can read, change, and delete any inventory,
team, or organization where `organization_id = 1` (AWX_community). For the
organization resource itself, the filter uses `id = 1` since organizations
don't have an `organization_id` field.

### OPA query: "Can org_admin read inventories?"

**Input:**

```bash
curl -s -X POST http://localhost:8181/v1/data/dab_opa \
  -H 'Content-Type: application/json' \
  -d '{
    "input": {
      "principal": {"user_id": 6, "is_superuser": false},
      "target": {"resource": "inventory", "action": "read"}
    }
  }' | jq '.result'
```

**Output:**

```json
{
  "allow": true,
  "clauses": [
    { "field_name": "organization_id", "operator": "eq", "value": 1 }
  ]
}
```

**Django compiles this to:**

```python
Inventory.objects.filter(Q(organization_id=1))
```

This returns only inventories in AWX_community (e.g., "AWX deployment",
"CustomUser Inventory").

### OPA query: "Can org_admin read instance groups?"

```bash
curl -s -X POST http://localhost:8181/v1/data/dab_opa \
  -H 'Content-Type: application/json' \
  -d '{
    "input": {
      "principal": {"user_id": 6, "is_superuser": false},
      "target": {"resource": "instancegroup", "action": "read"}
    }
  }' | jq '.result'
```

```json
{
  "allow": false,
  "clauses": []
}
```

org_admin has no instance group permissions — their role is scoped to the
AWX_community organization, and instance groups are not org-scoped resources.

---

## Persona 2: angry_spud (Team Member with Object Permissions)

The `angry_spud` user is a member of the `awx_devs` team, which has Inventory
Admin on specific inventories (AWX deployment, Galaxy Host). angry_spud also
has a direct Custom Inventory Viewer assignment on AWX deployment.

### Policy data in OPA

```bash
curl -s http://localhost:8181/v1/data/dab_opa/user_policies | \
  jq '.result["3"]'
```

```json
{
  "inventory": {
    "read": [
      { "field_name": "id", "operator": "eq", "value": 2, "value_type": "constant" },
      { "field_name": "id", "operator": "eq", "value": 3, "value_type": "constant" }
    ],
    "change": [
      { "field_name": "id", "operator": "eq", "value": 2, "value_type": "constant" },
      { "field_name": "id", "operator": "eq", "value": 3, "value_type": "constant" }
    ]
  },
  "team": {
    "read": [
      { "field_name": "id", "operator": "eq", "value": 2, "value_type": "constant" }
    ]
  }
}
```

**What this means:** angry_spud can read and change inventories with `id = 2`
(Galaxy Host) and `id = 3` (AWX deployment). They can also read team `id = 2`
(awx_devs, since they're a member). Note the object-level `id` filter rather
than the org-level `organization_id` filter — team-inherited permissions are
on specific objects, not whole orgs.

### OPA query: "Can angry_spud read inventories?"

**Input:**

```bash
curl -s -X POST http://localhost:8181/v1/data/dab_opa \
  -H 'Content-Type: application/json' \
  -d '{
    "input": {
      "principal": {"user_id": 3, "is_superuser": false},
      "target": {"resource": "inventory", "action": "read"}
    }
  }' | jq '.result'
```

**Output:**

```json
{
  "allow": true,
  "clauses": [
    { "field_name": "id", "operator": "eq", "value": 2 },
    { "field_name": "id", "operator": "eq", "value": 3 }
  ]
}
```

**Django compiles this to:**

```python
Inventory.objects.filter(Q(id=2) | Q(id=3))
```

Multiple clauses with the same field are OR'd together. This returns "Galaxy
Host" and "AWX deployment" but not "K8S clusters" or any other inventory.

---

## Persona 3: instance_group_admin

The `instance_group_admin` user has the AWX InstanceGroup Admin role on the
"Isolated Network" instance group. They have no inventory or organization
permissions.

### Policy data in OPA

```bash
curl -s http://localhost:8181/v1/data/dab_opa/user_policies | \
  jq '.result["7"]'
```

```json
{
  "instancegroup": {
    "read": [
      { "field_name": "id", "operator": "eq", "value": 2, "value_type": "constant" }
    ],
    "change": [
      { "field_name": "id", "operator": "eq", "value": 2, "value_type": "constant" }
    ],
    "delete": [
      { "field_name": "id", "operator": "eq", "value": 2, "value_type": "constant" }
    ]
  }
}
```

### OPA query: "Can instance_group_admin read instance groups?"

```bash
curl -s -X POST http://localhost:8181/v1/data/dab_opa \
  -H 'Content-Type: application/json' \
  -d '{
    "input": {
      "principal": {"user_id": 7, "is_superuser": false},
      "target": {"resource": "instancegroup", "action": "read"}
    }
  }' | jq '.result'
```

```json
{
  "allow": true,
  "clauses": [
    { "field_name": "id", "operator": "eq", "value": 2 }
  ]
}
```

**Django compiles this to:**

```python
InstanceGroup.objects.filter(Q(id=2))
```

Returns only "Isolated Network".

---

## Persona 4: multi_org_user (Cross-Organization Admin)

The `multi_org_user` has Organization Admin in both AWX_community and
Galaxy_community. This demonstrates how multiple org-scoped policies combine.

### Policy data in OPA

```bash
curl -s http://localhost:8181/v1/data/dab_opa/user_policies | \
  jq '.result["8"]'
```

```json
{
  "inventory": {
    "read": [
      { "field_name": "organization_id", "operator": "eq", "value": 1, "value_type": "constant" },
      { "field_name": "organization_id", "operator": "eq", "value": 2, "value_type": "constant" }
    ],
    "change": [
      { "field_name": "organization_id", "operator": "eq", "value": 1, "value_type": "constant" },
      { "field_name": "organization_id", "operator": "eq", "value": 2, "value_type": "constant" }
    ],
    "delete": [
      { "field_name": "organization_id", "operator": "eq", "value": 1, "value_type": "constant" },
      { "field_name": "organization_id", "operator": "eq", "value": 2, "value_type": "constant" }
    ]
  },
  "organization": {
    "read": [
      { "field_name": "id", "operator": "eq", "value": 1, "value_type": "constant" },
      { "field_name": "id", "operator": "eq", "value": 2, "value_type": "constant" }
    ],
    "change": [
      { "field_name": "id", "operator": "eq", "value": 1, "value_type": "constant" },
      { "field_name": "id", "operator": "eq", "value": 2, "value_type": "constant" }
    ]
  },
  "team": {
    "read": [
      { "field_name": "organization_id", "operator": "eq", "value": 1, "value_type": "constant" },
      { "field_name": "organization_id", "operator": "eq", "value": 2, "value_type": "constant" },
      { "field_name": "id", "operator": "eq", "value": 3, "value_type": "constant" }
    ],
    "change": [
      { "field_name": "organization_id", "operator": "eq", "value": 1, "value_type": "constant" },
      { "field_name": "organization_id", "operator": "eq", "value": 2, "value_type": "constant" }
    ],
    "delete": [
      { "field_name": "organization_id", "operator": "eq", "value": 1, "value_type": "constant" },
      { "field_name": "organization_id", "operator": "eq", "value": 2, "value_type": "constant" }
    ]
  }
}
```

### OPA query: "Can multi_org_user read inventories?"

```bash
curl -s -X POST http://localhost:8181/v1/data/dab_opa \
  -H 'Content-Type: application/json' \
  -d '{
    "input": {
      "principal": {"user_id": 8, "is_superuser": false},
      "target": {"resource": "inventory", "action": "read"}
    }
  }' | jq '.result'
```

```json
{
  "allow": true,
  "clauses": [
    { "field_name": "organization_id", "operator": "eq", "value": 1 },
    { "field_name": "organization_id", "operator": "eq", "value": 2 }
  ]
}
```

**Django compiles this to:**

```python
Inventory.objects.filter(Q(organization_id=1) | Q(organization_id=2))
```

Returns inventories from both AWX_community and Galaxy_community.

---

## Persona 5: admin (Superuser)

Superusers bypass all policy evaluation. OPA returns `allow: true` with an
empty clause list, meaning Django applies no filters to the queryset.

### OPA query: "Can admin delete inventories?"

```bash
curl -s -X POST http://localhost:8181/v1/data/dab_opa \
  -H 'Content-Type: application/json' \
  -d '{
    "input": {
      "principal": {"user_id": 2, "is_superuser": true},
      "target": {"resource": "inventory", "action": "delete"}
    }
  }' | jq '.result'
```

```json
{
  "allow": true,
  "clauses": []
}
```

**Django compiles this to:**

```python
Inventory.objects.all()   # no filter applied
```

The superuser sees everything. Note that `is_superuser: true` is evaluated
in the Rego rules before any policy data lookup, so superusers don't need
entries in `user_policies` at all.

---

## Persona 6: ansibullbot (No Permissions)

A user with no role assignments has no entry in the policy data. OPA returns
`allow: false` with no clauses.

### OPA query: "Can ansibullbot read inventories?"

```bash
curl -s -X POST http://localhost:8181/v1/data/dab_opa \
  -H 'Content-Type: application/json' \
  -d '{
    "input": {
      "principal": {"user_id": 5, "is_superuser": false},
      "target": {"resource": "inventory", "action": "read"}
    }
  }' | jq '.result'
```

```json
{
  "allow": false,
  "clauses": []
}
```

**Django compiles this to:**

```python
Inventory.objects.none()   # empty queryset
```

The user gets an empty list, not a 403. This is the standard behavior for
list endpoints — no permission means zero results, not an error.

---

## Persona 7: auditor_user (System Auditor)

The System Auditor has a global role that grants view access to all resources
across all organizations. During migration, this is expanded into per-org and
per-object policies covering every existing org and non-org-scoped object.

### Policy data in OPA

```bash
curl -s http://localhost:8181/v1/data/dab_opa/user_policies | \
  jq '.result["9"]'
```

The auditor's data will include read clauses for every organization, every
inventory org, every team org, and every instance group — one clause per
existing object or org:

```json
{
  "inventory": {
    "read": [
      { "field_name": "organization_id", "operator": "eq", "value": 1, "value_type": "constant" },
      { "field_name": "organization_id", "operator": "eq", "value": 2, "value_type": "constant" },
      { "field_name": "organization_id", "operator": "eq", "value": 3, "value_type": "constant" }
    ]
  },
  "organization": {
    "read": [
      { "field_name": "id", "operator": "eq", "value": 1, "value_type": "constant" },
      { "field_name": "id", "operator": "eq", "value": 2, "value_type": "constant" },
      { "field_name": "id", "operator": "eq", "value": 3, "value_type": "constant" }
    ]
  },
  "instancegroup": {
    "read": [
      { "field_name": "id", "operator": "eq", "value": 1, "value_type": "constant" },
      { "field_name": "id", "operator": "eq", "value": 2, "value_type": "constant" }
    ]
  },
  "team": {
    "read": [
      { "field_name": "organization_id", "operator": "eq", "value": 1, "value_type": "constant" },
      { "field_name": "organization_id", "operator": "eq", "value": 2, "value_type": "constant" },
      { "field_name": "organization_id", "operator": "eq", "value": 3, "value_type": "constant" }
    ]
  }
}
```

**Note:** The exact org and object IDs depend on your data. The System Auditor
migration expands "view everything" into explicit clauses for each existing
org/object, since OPA doesn't have a concept of "all" — it needs concrete
values to match against.

---

## How clause compilation works

When OPA returns multiple clauses, Django combines them:

| Clauses | Django Q() | SQL equivalent |
|---------|------------|----------------|
| `[{field: "organization_id", op: "eq", value: 1}]` | `Q(organization_id=1)` | `WHERE organization_id = 1` |
| `[{field: "id", op: "eq", value: 2}, {field: "id", op: "eq", value: 3}]` | `Q(id=2) \| Q(id=3)` | `WHERE id = 2 OR id = 3` |
| `[{field: "organization_id", op: "eq", value: 1}, {field: "organization_id", op: "eq", value: 2}]` | `Q(organization_id=1) \| Q(organization_id=2)` | `WHERE organization_id IN (1, 2)` |
| `[]` (superuser) | no filter | `(no WHERE clause)` |
| `[]` (no access) | `.none()` | `WHERE 1=0` |

The difference between "superuser empty clauses" and "no access empty clauses"
is the `allow` flag — `allow: true` with empty clauses means "everything",
`allow: false` with empty clauses means "nothing".

---

## Producing examples for your own users

If you have a specific user and want to see exactly what OPA data and
responses look like for them, follow these steps:

### Step 1: Find the user's ID

```bash
curl -s -u admin:admin http://localhost:8000/api/v1/users/ | \
  jq '.results[] | {id, username}'
```

Or from the Django shell:

```bash
python manage.py shell -c "from django.contrib.auth import get_user_model; print([(u.pk, u.username) for u in get_user_model().objects.all()])"
```

### Step 2: View their policy data in OPA

Replace `USER_ID` with the actual ID:

```bash
curl -s http://localhost:8181/v1/data/dab_opa/user_policies | \
  jq '.result["USER_ID"]'
```

If the result is `null`, the user has no OPA policies (either no RBAC roles
were migrated, or no OPA roles were directly assigned).

### Step 3: Query OPA for a specific resource and action

```bash
curl -s -X POST http://localhost:8181/v1/data/dab_opa \
  -H 'Content-Type: application/json' \
  -d '{
    "input": {
      "principal": {"user_id": USER_ID, "is_superuser": false},
      "target": {"resource": "RESOURCE", "action": "ACTION"}
    }
  }' | jq '.result'
```

Replace `USER_ID`, `RESOURCE` (e.g., `inventory`, `organization`,
`instancegroup`, `team`), and `ACTION` (e.g., `read`, `change`, `delete`).

### Step 4: Use the effective scope API

The Django API provides an introspection endpoint that queries OPA and returns
the result:

```bash
curl -s -u admin:admin \
  "http://localhost:8000/api/v1/opa/effective_scope/?user_id=USER_ID&resource=RESOURCE&action=ACTION" \
  | jq .
```

### Step 5: Compare with the actual API response

Make a request as the user to see what they actually get:

```bash
curl -s -u USERNAME:password http://localhost:8000/api/v1/inventories/ | \
  jq '{count: .count, items: [.results[].name]}'
```

### Step 6: View the local data.json

The sync also writes all policy data to a local file for debugging:

```bash
python -m json.tool ansible_base/opa/bundles/data.json | \
  jq '.user_policies["USER_ID"]'
```

### Step 7: Check all resources for a user

To see everything a user can access across all resources and actions:

```bash
for resource in inventory organization team instancegroup; do
  for action in read change delete; do
    result=$(curl -s -X POST http://localhost:8181/v1/data/dab_opa \
      -H 'Content-Type: application/json' \
      -d "{\"input\":{\"principal\":{\"user_id\":USER_ID,\"is_superuser\":false},\"target\":{\"resource\":\"$resource\",\"action\":\"$action\"}}}" \
      | jq -r '.result.allow')
    if [ "$result" = "true" ]; then
      echo "$resource/$action: ALLOWED"
    fi
  done
done
```

### Step 8: View the Rego rules

To see the actual Rego policy that OPA evaluates:

```bash
curl -s http://localhost:8181/v1/policies | jq '.result[].raw' -r
```

This shows the Rego source code. The key rules are:
- `allow` — checks `is_superuser` first, then looks up user policies
- `clauses` — extracts the filter clauses for the matching resource/action
- The rules reference `data.dab_opa.user_policies` — the pre-flattened data
  pushed from Django

---

## Key patterns to notice

1. **Org-scoped resources** (inventory, team) filter on `organization_id`.
   The organization resource itself filters on `id`.

2. **Object-level permissions** (from direct assignments or team-inherited
   roles) filter on `id` — the specific object's PK.

3. **Multiple clauses are OR'd** — if a user has access to org 1 and org 2,
   they get two clauses that combine to `WHERE org_id = 1 OR org_id = 2`.

4. **Superusers skip policy lookup** — the Rego rule checks `is_superuser`
   first and returns `allow: true` with no clauses.

5. **No entry = no access** — users without policy data get `allow: false`.

6. **Actions are independent** — having `read` access doesn't imply `change`
   or `delete`. Each action has its own clause set.
