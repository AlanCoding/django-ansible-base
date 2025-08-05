# Claims Hashing

## Overview

Claims hashing provides a deterministic way to generate a unique fingerprint for a user's permission set. This hash can be used for:

- JWT token validation and caching
- Permission change detection
- Audit logging and compliance tracking
- Performance optimization in permission checks

## How Claims Hashing Works

### 1. Claims Generation

The `get_user_claims(user)` function generates a claims dictionary containing:

```python
{
    'global_roles': ['Platform Auditor', 'System Admin'],
    'object_roles': {
        'Organization Admin': {
            'content_type': 'organization',
            'objects': [0, 2, 5]  # Indexes into objects array
        },
        'Team Member': {
            'content_type': 'team', 
            'objects': [0, 1, 3]
        }
    },
    'objects': {
        'organization': [
            {'ansible_id': 'a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'name': 'Engineering Org'},
            {'ansible_id': 'f9e8d7c6-b5a4-3210-9876-543210fedcba', 'name': 'Sales Org'}
        ],
        'team': [
            {'ansible_id': '12345678-90ab-cdef-1234-567890abcdef', 'name': 'Backend Team', 'org': 0},
            {'ansible_id': '87654321-dcba-0987-6543-210fedcba098', 'name': 'Frontend Team', 'org': 1}
        ]
    }
}
```

### 2. Hashable Form Conversion

Before hashing, the claims are converted to a "hashable form" that:

- **Uses ansible_id instead of names**: Object names can change, but ansible_id is immutable
- **Sorts all collections deterministically**: Ensures consistent ordering regardless of database query order
- **Resolves object references**: Converts index references to actual ansible_id values
- **Removes volatile data**: Excludes timestamps, names, and other non-permission data

Example hashable form:
```python
{
    'global_roles': ['Platform Auditor', 'System Admin'],  # Sorted
    'object_roles': {
        'Organization Admin': ['a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'f9e8d7c6-b5a4-3210-9876-543210fedcba'],  # Sorted ansible_ids
        'Team Member': ['12345678-90ab-cdef-1234-567890abcdef', '87654321-dcba-0987-6543-210fedcba098']        # Sorted ansible_ids
    }
}
```

### 3. Hash Generation

The hashable form is:
1. Serialized to JSON with sorted keys
2. Encoded to UTF-8 bytes
3. Hashed using SHA-256
4. Returned as a hexadecimal string

## Properties of Claims Hashing

### Deterministic
- Same permission set always produces the same hash
- Independent of:
  - User identity (different users with same permissions = same hash)
  - Object names (renaming organizations/teams doesn't change hash)
  - Assignment order (permissions removed and re-added produce same hash)
  - Database query order (sorting ensures consistency)

### Immutable Reference-Based
- Hash is based on `ansible_id` values, not database IDs or names
- Survives object renames, moves between databases, etc.
- Only changes when actual permissions change

### Collision Resistant
- Uses SHA-256 cryptographic hash function
- Extremely low probability of different permission sets producing same hash

## Use Cases

### JWT Token Validation
```python
# Generate hash for current user permissions
current_hash = get_user_claims_hash(user)

# Compare with hash in JWT token
if current_hash != jwt_payload.get('permissions_hash'):
    # Permissions changed, token invalid
    raise PermissionError("Token permissions outdated")
```

### Permission Change Detection
```python
# Store hash after permission change
old_hash = user.permissions_hash
new_hash = get_user_claims_hash(user)

if old_hash != new_hash:
    # Log permission change for audit
    audit_log.info(f"User {user.id} permissions changed: {old_hash} -> {new_hash}")
```

### Caching
```python
# Use hash as cache key for expensive permission computations
cache_key = f"user_permissions:{get_user_claims_hash(user)}"
accessible_resources = cache.get(cache_key)
if not accessible_resources:
    accessible_resources = compute_accessible_resources(user)
    cache.set(cache_key, accessible_resources, timeout=3600)
```

## Implementation Details

### Supported Content Types
- Organizations
- Teams  
- Any registered RBAC model with ansible_id

### Global vs Object Roles
- **Global roles**: Platform-wide permissions (Platform Auditor, System Admin)
- **Object roles**: Permissions scoped to specific resources (Organization Admin, Team Member)

### Performance Considerations
- Claims generation involves database queries - consider caching
- Hash computation is fast (SHA-256 on small JSON)
- Hashable form conversion does sorting - O(n log n) complexity

## Security Notes

- Hash reveals no information about actual permissions (one-way function)
- Safe to log, store, and transmit hashes
- Cannot be reversed to determine permission details
- Collision resistance makes hash tampering detectable 