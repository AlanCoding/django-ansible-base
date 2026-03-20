package dab_opa

import rego.v1

default allow := false

# Superuser bypass
allow if {
    input.principal.is_superuser == true
}

# Placeholder: returns empty clauses for all requests.
# This will be replaced by dynamically generated policy.
clauses := []
