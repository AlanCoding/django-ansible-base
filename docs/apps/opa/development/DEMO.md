# DAB OPA Demo Walkthrough

This is a hands-on walkthrough of the DAB OPA authorization system. It covers
setup, RBAC migration, direct OPA interaction, the management API, and live
request filtering with policy-based access control.

You'll need two terminal tabs: one for infrastructure and one for the Django
development server.

---

## 1. Start infrastructure

**Tab 1** — start Postgres and OPA:

```bash
make postgres
make opa
```

Wait for both containers to be healthy:

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}'
```

You should see:

```
NAMES          STATUS
dab_opa        Up ... (healthy)
dab_postgres   Up ... (healthy)
```

---

## 2. Bootstrap the database

**Tab 1** — migrate, create the admin user, and load demo data:

```bash
python manage.py migrate
DJANGO_SUPERUSER_PASSWORD=admin python manage.py createsuperuser --noinput --username admin --email admin@example.com
python manage.py authenticators --initialize
python manage.py create_demo_data
```

---

## 3. Migrate RBAC data to OPA

The demo data includes RBAC role assignments (org admins, inventory admins,
system auditor, custom roles, team assignments). The migration command converts
all of those into OPA roles, policies, groups, and assignments:

```bash
python manage.py migrate_rbac_to_opa --sync
```

The `--sync` flag pushes the resulting policy data to OPA immediately.

To see what *would* be migrated without writing anything:

```bash
python manage.py migrate_rbac_to_opa --dry-run
```

---

## 4. Start the Django server

**Tab 2** — start the development server:

```bash
python manage.py runserver
```

Leave this running. All `curl` commands below talk to `localhost:8000`.

---

## 5. Inspect OPA directly

OPA is running on `localhost:8181`. These commands demonstrate the OPA server
independently of Django.

### 5.1 Health check

```bash
curl -s http://localhost:8181/health | jq .
```

```json
{}
```

An empty `{}` means healthy.

### 5.2 View the loaded Rego policy

OPA can show you the Rego rules it has loaded:

```bash
curl -s http://localhost:8181/v1/policies | jq '.result[].raw' -r
```

This prints the `policy.rego` source — the Rego rules that evaluate user
access based on the pushed policy data.

### 5.3 View the policy data pushed from Django

After `migrate_rbac_to_opa --sync`, OPA has a full data structure mapping
users to their permitted resources. Inspect it:

```bash
curl -s http://localhost:8181/v1/data/dab_opa/user_policies | jq '.result | keys'
```

This shows user IDs that have policy data. Pick one (the admin user is
typically `1`) and drill in:

```bash
# Replace USER_ID with an actual ID from the previous output
curl -s http://localhost:8181/v1/data/dab_opa/user_policies | jq '.result["2"]'
```

You'll see something like:

```json
{
  "inventory": {
    "read": [
      { "field_name": "organization_id", "operator": "eq", "value": 1, "value_type": "constant" }
    ],
    "change": [
      { "field_name": "organization_id", "operator": "eq", "value": 1, "value_type": "constant" }
    ]
  },
  "organization": {
    "read": [
      { "field_name": "id", "operator": "eq", "value": 1, "value_type": "constant" }
    ]
  }
}
```

This is the pre-flattened policy data. OPA doesn't need to traverse any
relationships — it's a direct lookup by user ID, resource, and action.

### 5.4 Query OPA directly (scope resolution)

Ask OPA what a specific user can do:

```bash
# What can user 2 read from inventory?
curl -s -X POST http://localhost:8181/v1/data/dab_opa \
  -H 'Content-Type: application/json' \
  -d '{"input":{"principal":{"user_id":2,"is_superuser":false},"target":{"resource":"inventory","action":"read"}}}' \
  | jq '.result'
```

```json
{
  "allow": true,
  "clauses": [
    { "field_name": "organization_id", "operator": "eq", "value": 1 }
  ]
}
```

This means: "yes, user 2 can read inventories, but only those where
`organization_id = 1`." Django takes these clauses and compiles them into a
queryset filter: `Inventory.objects.filter(organization_id=1)`.

Now try a user with no permissions:

```bash
curl -s -X POST http://localhost:8181/v1/data/dab_opa \
  -H 'Content-Type: application/json' \
  -d '{"input":{"principal":{"user_id":99999,"is_superuser":false},"target":{"resource":"inventory","action":"read"}}}' \
  | jq '.result'
```

```json
{
  "allow": false,
  "clauses": []
}
```

No clauses, no access.

### 5.5 Superuser bypass

```bash
curl -s -X POST http://localhost:8181/v1/data/dab_opa \
  -H 'Content-Type: application/json' \
  -d '{"input":{"principal":{"user_id":1,"is_superuser":true},"target":{"resource":"inventory","action":"delete"}}}' \
  | jq '.result'
```

```json
{
  "allow": true,
  "clauses": []
}
```

Superusers are allowed with no clauses — they get the full unfiltered queryset.

### 5.6 View the data.json file

The sync also writes the data to a local JSON file for debugging:

```bash
cat ansible_base/opa/bundles/data.json | python3 -m json.tool | head -40
```

---

## 6. OPA parity check

Verify that the OPA evaluator and the local Django evaluator agree on every
user/resource/action combination:

```bash
python manage.py opa_parity_check
```

This iterates all users, all resources, and all actions, comparing OPA (via
HTTP) with the local evaluator (pure Django DB queries). A passing run shows:

```
All parity checks passed!
```

Use `--verbose` to see the OPA clauses for each check:

```bash
python manage.py opa_parity_check --verbose
```

---

## 7. Django API — observe OPA in action

Now we'll make API requests as different users and see OPA filtering the
results. The demo data creates several users with different permission levels.

### 7.1 Admin sees everything

```bash
curl -s -u admin:admin http://localhost:8000/api/v1/inventories/ \
  | jq '{count: .count, inventories: [.results[].name]}'
```

The admin (superuser) sees all inventories.

### 7.2 Org admin sees only their org's inventories

The `org_admin` user was given Organization Admin on the AWX_community org:

```bash
curl -s -u org_admin:password http://localhost:8000/api/v1/inventories/ \
  | jq '{count: .count, inventories: [.results[].name]}'
```

This should return only inventories belonging to AWX_community.

### 7.3 Instance group admin sees instance groups, not inventories

The `instance_group_admin` user has permissions on instance groups only:

```bash
# Can see instance groups
curl -s -u instance_group_admin:password http://localhost:8000/api/v1/instance_groups/ \
  | jq '{count: .count, groups: [.results[].name]}'

# Cannot see inventories
curl -s -u instance_group_admin:password http://localhost:8000/api/v1/inventories/ \
  | jq '{count: .count}'
```

### 7.4 Multi-org user sees inventories from both orgs

The `multi_org_user` was given org admin in both AWX_community and
Galaxy_community:

```bash
curl -s -u multi_org_user:password http://localhost:8000/api/v1/inventories/ \
  | jq '{count: .count, inventories: [.results[].name]}'
```

### 7.5 Unpermissioned user sees nothing

A user with no role assignments gets zero results (not a 403 — the list just
returns empty):

```bash
curl -s -u ansibullbot:password http://localhost:8000/api/v1/inventories/ \
  | jq '{count: .count, inventories: [.results[].name]}'
```

```json
{
  "count": 0
}
```

---

## 8. OPA management API

The OPA management API lets admins create roles, policies, groups, and
assignments via REST.

### 8.1 List existing OPA roles

```bash
curl -s -u admin:admin http://localhost:8000/api/v1/opa_roles/ \
  | jq '{count: .count, roles: [.results[] | {name, policy_count: (.policies | length)}]}'
```

### 8.2 Create a new role with a policy

```bash
# Create a role
ROLE_ID=$(curl -s -u admin:admin http://localhost:8000/api/v1/opa_roles/ \
  -H 'Content-Type: application/json' \
  -d '{"name": "demo-inv-reader", "description": "Demo: read inventories in org 1"}' \
  | jq -r '.id')
echo "Created role: $ROLE_ID"

# Add a policy to the role
curl -s -u admin:admin http://localhost:8000/api/v1/opa_policies/ \
  -H 'Content-Type: application/json' \
  -d "{\"role\": $ROLE_ID, \"resource\": \"inventory\", \"action\": \"read\", \"field_name\": \"organization_id\", \"operator\": \"eq\", \"value_type\": \"constant\", \"constant_value\": \"1\"}" \
  | jq '{id, resource, action, field_name, constant_value}'
```

### 8.3 Create a group and assign the role

```bash
# Create a group
GROUP_ID=$(curl -s -u admin:admin http://localhost:8000/api/v1/opa_groups/ \
  -H 'Content-Type: application/json' \
  -d '{"name": "demo-readers"}' \
  | jq -r '.id')
echo "Created group: $GROUP_ID"

# Add ansibullbot to the group (get their user ID first)
BULL_ID=$(curl -s -u admin:admin "http://localhost:8000/api/v1/users/?username=ansibullbot" \
  | jq -r '.results[0].id')
curl -s -u admin:admin "http://localhost:8000/api/v1/opa_groups/$GROUP_ID/add_user/" \
  -H 'Content-Type: application/json' \
  -d "{\"user_id\": $BULL_ID}" \
  | jq .

# Assign the role to the group
curl -s -u admin:admin http://localhost:8000/api/v1/opa_group_role_assignments/ \
  -H 'Content-Type: application/json' \
  -d "{\"group\": $GROUP_ID, \"role\": $ROLE_ID}" \
  | jq '{id, group, role}'
```

### 8.4 Sync to OPA and verify

```bash
python manage.py sync_opa
```

Now ansibullbot (who had zero access before) can see inventories in org 1:

```bash
curl -s -u ansibullbot:password http://localhost:8000/api/v1/inventories/ \
  | jq '{count: .count, inventories: [.results[].name]}'
```

### 8.5 Introspect effective scope

The effective scope endpoint shows what OPA would grant for a user/resource/action:

```bash
curl -s -u admin:admin \
  "http://localhost:8000/api/v1/opa/effective_scope/?user_id=$BULL_ID&resource=inventory&action=read" \
  | jq .
```

```json
{
  "resource": "inventory",
  "action": "read",
  "allow": true,
  "clauses": [
    { "field_name": "organization_id", "operator": "eq", "value": 1 }
  ]
}
```

---

## 9. Django admin UI

The OPA app includes full Django admin pages for managing roles, policies,
groups, and assignments. Navigate to:

```
http://localhost:8000/admin/
```

Log in as `admin`/`admin`. Under **DAB_OPA** you'll see:

- **Roles** — list with policy count, group count. Click a role to see its
  policies inline, with clickable links to the referenced objects (e.g., a
  policy that references `organization_id = 1` will show a link to "AWX_community").
- **Policies** — list with resource, action, filter, value, and object links.
  The add/edit form has **dropdown menus** for resource, action, and field name,
  populated from the OPA registry. When creating a policy with a constant
  value, click **Browse...** next to the value field to pick from existing
  objects (organizations, inventories, etc.) in a searchable popup.
- **OPA Groups** — list with user count and role count. The detail view shows a
  horizontal filter widget for managing group membership, inline role
  assignments, and an **Effective Permissions** summary table showing every
  permission the group's users receive (role, resource, action, filter
  condition, and a link to the referenced object).
- **Group Role Assignments** — list with clickable links to both the group and
  role. Uses autocomplete for the group and role dropdowns.

### Admin actions

All list views include a **"Sync to OPA"** action in the action dropdown.
Select any items and run the action to push the current policy data to the
OPA server.

### Creating a role via admin

1. Go to **Roles > Add Role**
2. Enter a name and description
3. In the **Policies** inline section, select a resource (e.g., "inventory"),
   action (e.g., "read"), field (e.g., "organization_id"), and click
   **Browse...** to pick the target organization
4. Save the role
5. Go to **OPA Groups**, pick a group, and in the **Group Role Assignments**
   inline, assign the new role
6. Use the **Sync to OPA** action to push changes

---

## 10. Transition validation (dual-evaluation mode)

When migrating from RBAC to OPA, you can enable dual-evaluation to compare
both systems on every request and log discrepancies.

In your Django settings:

```python
DAB_OPA_TRANSITION_VALIDATION = True
```

With this enabled, every `filter_queryset_for_user()` and
`user_can_access_obj()` call also runs the equivalent RBAC check and compares
results. Mismatches are logged at ERROR level:

```
ERROR ansible_base.opa.transition TRANSITION MISMATCH queryset user=some_user resource=inventory action=read opa_count=3 rbac_count=2 opa_only={5} rbac_only={}
```

Matches are logged at DEBUG level. OPA is always the authoritative result.

You can also do a batch comparison with the verify command:

```bash
python manage.py migrate_rbac_to_opa --verify
```

---

## 11. Detailed examples

For concrete examples of the OPA input/output for each user persona — including
the pre-flattened policy data, OPA query payloads, responses, and how Django
compiles clauses into queryset filters — see [EXAMPLES.md](EXAMPLES.md).

That document also includes step-by-step instructions for producing this data
for any arbitrary user in your system.

---

## 12. Architecture summary

```
                                   +-----------+
 User Request                      |   OPA     |
     |                             | (sidecar) |
     v                             |  :8181    |
 +--------+    scope resolution    +-----+-----+
 | Django  | --------------------> |     |
 | (DRF)  | <-- clauses ---------- |     |
 +---+----+                        +-----------+
     |
     | queryset.filter(Q(organization_id=1) | Q(id=5))
     v
 +--------+
 |Postgres|
 +--------+
```

1. Django asks OPA: "what can user X do with resource Y, action Z?"
2. OPA looks up the user's pre-flattened policy data and returns **clauses**
3. Django compiles clauses into `Q()` objects and filters the queryset
4. Postgres returns only the rows the user is authorized to see

Policy data is pushed to OPA via `PUT /v1/data/dab_opa/user_policies`
whenever roles, policies, groups, or assignments change. OPA doesn't query
Django — it holds a snapshot of all authorization data in memory.

---

## Command reference

| Step | Command | What it does |
|------|---------|--------------|
| Start infra | `make postgres && make opa` | Postgres + OPA containers |
| Migrate DB | `python manage.py migrate` | Django schema migrations |
| Create data | `python manage.py create_demo_data` | RBAC demo data |
| Migrate to OPA | `python manage.py migrate_rbac_to_opa --sync` | RBAC -> OPA + push to OPA |
| Parity check | `python manage.py opa_parity_check` | Compare OPA vs local evaluator |
| Sync OPA | `python manage.py sync_opa` | Re-push policy data to OPA |
| Verify | `python manage.py migrate_rbac_to_opa --verify` | Compare OPA vs RBAC for all users |
| Run server | `python manage.py runserver` | Django dev server |
