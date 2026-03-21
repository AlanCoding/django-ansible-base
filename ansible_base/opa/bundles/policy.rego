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

# Resolve clauses for the given user/resource/action
clauses := resolved if {
	user_id := format_int(input.principal.user_id, 10)
	policies := data.dab_opa.user_policies[user_id][input.target.resource][input.target.action]
	resolved := [clause |
		some p in policies
		clause := _resolve_clause(p)
	]
}

# Default empty clauses when no policies match
default clauses := []

# Substitute principal_user_id with actual user_id
_resolve_clause(p) := {"field_name": p.field_name, "operator": p.operator, "value": input.principal.user_id} if {
	p.value_type == "principal_user_id"
}

# Pass through constant values as-is
_resolve_clause(p) := {"field_name": p.field_name, "operator": p.operator, "value": p.value} if {
	p.value_type == "constant"
}
