# OPA Parity Demo

Verify that OPA and the local Django evaluator produce identical authorization results for all users in the system.

## Prerequisites

- Docker (for postgres and OPA containers)
- Python virtualenv at `~/venvs/awx/` (or adjust paths below)

## 1. Start services and bootstrap

```bash
make postgres
make opa
```

Wait for both containers to be healthy:

```bash
docker ps --format '{{.Names}} {{.Status}}'
# Should show:
#   dab_postgres  Up ... (healthy)
#   dab_opa       Up ... (healthy)
```

## 2. Migrate and create demo data

```bash
python manage.py migrate
python manage.py create_demo_data
```

This creates the standard test_app demo data: organizations, users, teams, inventories, and RBAC role assignments.

## 3. Migrate RBAC data to OPA

```bash
python manage.py migrate_rbac_to_opa --sync
```

This reads all existing RBAC `RoleDefinition`s, `RoleUserAssignment`s, and `RoleTeamAssignment`s and creates equivalent OPA roles, policies, and group assignments. The `--sync` flag pushes the result to OPA immediately.

Use `--dry-run` to see what would be migrated without writing anything:

```bash
python manage.py migrate_rbac_to_opa --dry-run
```

The command is idempotent -- safe to run multiple times.

## 4. Run the parity check

```bash
python manage.py opa_parity_check
```

This checks **every user** in the system against **every registered OPA resource and action**. For each combination it:

1. Queries OPA for the user's effective access (via HTTP)
2. Queries the local Django evaluator (pure DB, no OPA)
3. Compares the resulting querysets

A passing run ends with: `All parity checks passed!`

### Options

```bash
# Check a single user
python manage.py opa_parity_check --user alice

# Check a single resource
python manage.py opa_parity_check --resource inventory

# Show OPA clause details
python manage.py opa_parity_check --verbose

# Skip re-sync (if OPA is already up to date)
python manage.py opa_parity_check --no-sync
```

## 5. Verify manually

Data is left in place for manual inspection.

### Query OPA directly

```bash
# Replace USER_PK with an actual user pk
curl -s -X POST http://localhost:8181/v1/data/dab_opa \
  -H 'Content-Type: application/json' \
  -d '{"input":{"principal":{"user_id":USER_PK,"is_superuser":false},"target":{"resource":"inventory","action":"read"}}}' \
  | python3 -m json.tool
```

### Query via Django shell

```bash
python manage.py shell
```

```python
from django.contrib.auth import get_user_model
from test_app.models import Inventory
from ansible_base.lib.opa.queryset import filter_queryset_for_user, user_can_access_obj
from ansible_base.lib.opa.evaluator import local_filter_queryset

User = get_user_model()
user = User.objects.get(username='admin')

# What can this user read? (via OPA)
qs = filter_queryset_for_user(Inventory.objects.all(), user, 'read')
print([i.name for i in qs])

# Same check via local evaluator (no OPA call)
qs2 = local_filter_queryset(Inventory.objects.all(), user, 'read')
print([i.name for i in qs2])  # Should match
```

### Inspect the generated OPA data

```bash
cat ansible_base/lib/opa/bundles/data.json | python3 -m json.tool
```

### Re-sync after manual changes

```bash
python manage.py sync_opa
```

## Command summary

| Step | Command | What it does |
|------|---------|--------------|
| Start infra | `make postgres && make opa` | Postgres + OPA containers |
| Migrate DB | `python manage.py migrate` | Django migrations |
| Create data | `python manage.py create_demo_data` | RBAC demo data (orgs, users, teams, roles) |
| Migrate to OPA | `python manage.py migrate_rbac_to_opa --sync` | RBAC -> OPA roles/policies/groups + push to OPA |
| Parity check | `python manage.py opa_parity_check` | Compare OPA vs local for all users |
