package dab_opa

import rego.v1

default allow := false

# Superuser bypass
allow if {
	input.principal.is_superuser == true
}

# Allow if user has any matching policies
allow if {
	count(clauses) > 0
}

# Resolve clauses from input.policies (sent by Django per-request)
clauses := resolved if {
	resolved := [clause |
		some p in input.policies
		clause := _resolve_clause(p)
	]
}

# Default empty clauses when no policies are provided
default clauses := []

# Substitute principal_user_id with actual user_id
_resolve_clause(p) := {"field_name": p.field_name, "operator": p.operator, "value": input.principal.user_id} if {
	p.value_type == "principal_user_id"
}

# Pass through constant values as-is
_resolve_clause(p) := {"field_name": p.field_name, "operator": p.operator, "value": p.value} if {
	p.value_type == "constant"
}

# --- Tier 2: Object evaluation ---
# When input.object is present, evaluate whether the specific object is allowed.
# This is the authoritative answer (unlike clauses which are best-effort for querysets).

default object_allowed := false

# Superuser bypass
object_allowed if {
	input.principal.is_superuser == true
}

# Check if the object's attributes match any of the user's policies
object_allowed if {
	some p in input.policies
	clause := _resolve_clause(p)
	_clause_matches_object(clause)
}

# A clause matches the object if the object's field equals the clause value
_clause_matches_object(clause) if {
	clause.operator == "eq"
	input.object[clause.field_name] == clause.value
}

# --- Related object checks ---
# Returns a set of field names where the related check failed.

related_denied contains field if {
	some field, check in input.related
	not _related_allowed(check)
}

# Superuser bypass for related checks
_related_allowed(check) if {
	input.principal.is_superuser == true
}

# Related object allowed if any of its policies match by ID
_related_allowed(check) if {
	some p in check.policies
	clause := _resolve_clause(p)
	clause.operator == "eq"
	clause.field_name == "id"
	clause.value == check.id
}

# Related object allowed if any of its policies match by org
_related_allowed(check) if {
	check.org_id
	some p in check.policies
	clause := _resolve_clause(p)
	clause.operator == "eq"
	clause.field_name == "organization_id"
	clause.value == check.org_id
}
