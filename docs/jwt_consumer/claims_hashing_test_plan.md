# Claims Hashing Test Plan

## Test Strategy

The claims hashing system must be thoroughly tested to ensure deterministic, secure, and reliable operation. Tests must verify that hashes are stable across various scenarios while being sensitive to actual permission changes.

## Test Setup

For consistency across tests, use this helper function:

```python
from ansible_base.rbac.claims import get_user_claims, get_user_claims_hashable_form, get_claims_hash

def get_user_permissions_hash(user):
    """Generate a hash for a user's permissions."""
    claims = get_user_claims(user)
    hashable_claims = get_user_claims_hashable_form(claims)
    return get_claims_hash(hashable_claims)
```

## Test Categories

### 1. Basic Functionality Tests

#### Test: Hash Generation
- **Objective**: Verify basic hash generation works
- **Setup**: User with simple permissions (1 org admin, 1 global role)
- **Verification**: 
  - Hash is 64-character hex string (SHA-256)
  - Hash is reproducible across multiple calls
  - Hash changes when permissions change

#### Test: Empty Permissions
- **Objective**: Handle users with no permissions
- **Setup**: User with no role assignments
- **Verification**: 
  - Generates valid hash for empty permission set
  - Hash differs from users with permissions

#### Test: API Workflow
- **Objective**: Verify the three-step API works correctly
- **Setup**: User with mixed permissions
- **Verification**:
  - `get_user_claims(user)` returns complete claims structure
  - `get_user_claims_hashable_form(claims)` converts to hashable form
  - `get_claims_hash(hashable_claims)` produces valid SHA-256 hash
  - Each step handles the output of the previous step correctly

### 2. Determinism Tests

#### Test: Same Permissions, Same Hash
- **Objective**: Identical permission sets produce identical hashes
- **Setup**: 
  - Create 2 users with identical permissions
  - Same organizations, teams, roles
- **Verification**: Both users produce identical hash using `get_user_permissions_hash()`

#### Test: Permission Order Independence  
- **Objective**: Assignment order doesn't affect hash
- **Setup**:
  - User A: Assign org1 admin, then org2 admin
  - User B: Assign org2 admin, then org1 admin
- **Verification**: Both users have same hash

#### Test: Database Query Order Independence
- **Objective**: Database result ordering doesn't affect hash
- **Setup**: 
  - Create 10 organizations with random names
  - Assign user admin to all organizations
  - Query multiple times with different ORDER BY clauses
- **Verification**: Hash remains constant across queries (due to sorting in hashable form)

#### Test: Removal and Re-addition
- **Objective**: Removing and re-adding same permission produces same hash
- **Setup**:
  1. User with org admin permission
  2. Record hash using `get_user_permissions_hash(user)`
  3. Remove org admin permission  
  4. Re-add same org admin permission
- **Verification**: Final hash matches original hash

### 3. Immutability Tests

#### Test: Object Rename Stability
- **Objective**: Renaming objects doesn't change hash
- **Setup**:
  1. User with org admin permission on "Engineering Org"
  2. Record hash using `get_user_permissions_hash(user)`
  3. Rename organization to "Development Org"
- **Verification**: Hash remains unchanged (based on ansible_id, not name)

#### Test: Object Move Stability
- **Objective**: Moving teams between orgs updates hash correctly
- **Setup**:
  1. User with team member permission on team in org1
  2. Record hash using `get_user_permissions_hash(user)`
  3. Move team to org2
- **Verification**: Hash changes (org reference changed in team object)

#### Test: Ansible ID Stability
- **Objective**: Hash based on ansible_id, not database ID
- **Setup**:
  1. Create user with permissions
  2. Record hash using `get_user_permissions_hash(user)`
  3. Export/import data to new database (new DB IDs, same ansible_ids)
- **Verification**: Hash remains unchanged

### 4. Scale and Sorting Tests

#### Test: Large Permission Set
- **Objective**: Handle users with extensive permissions
- **Setup**:
  - 10 organizations
  - 20 teams  
  - User with admin access to 5 orgs, member of 10 teams
  - Multiple global roles
- **Verification**: 
  - Hash generation completes in reasonable time (<100ms)
  - Hash is deterministic across runs
  - Memory usage is reasonable

#### Test: Sorting Consistency
- **Objective**: Verify all collections are sorted consistently
- **Setup**:
  - Create orgs/teams with names that sort differently than ansible_ids
  - Example: names ["B Org", "A Org"] vs ansible_ids ["a1b2c3d4-e5f6-...", "f9e8d7c6-b5a4-..."]
- **Verification**: Hash based on ansible_id sorting, not name sorting

#### Test: Unicode Handling
- **Objective**: Handle international characters in names
- **Setup**:
  - Organizations with Unicode names (中文, العربية, русский)
  - User with permissions on these orgs
- **Verification**: 
  - Hash generation succeeds
  - Hash is deterministic
  - Names don't affect hash (ansible_id based)

### 5. QuerySet Integration Tests

#### Test: QuerySet Annotation Accuracy
- **Objective**: Verify `get_user_object_roles()` QuerySet annotations are correct
- **Setup**: User with mixed organization and team permissions
- **Verification**:
  - `aid` annotation matches resource.ansible_id
  - `resource_name` annotation matches resource.name
  - `rd_name` annotation matches role_definition.name
  - QuerySet filtering works correctly for JWT-managed roles

#### Test: Team Organization Resolution
- **Objective**: Test team organization reference resolution
- **Setup**: User with team permissions where teams belong to different organizations
- **Verification**:
  - Team objects have correct 'org' field referencing organization array position
  - Missing organizations are added to arrays when needed
  - Hash is consistent regardless of whether user has explicit org permissions

### 6. Performance Tests

#### Test: Query Efficiency
- **Objective**: Verify database query count is optimal
- **Setup**: User with complex permission set (multiple orgs, teams, global roles)
- **Verification**:
  - Query count remains reasonable (baseline: ~6 queries for complex scenarios)
  - No N+1 query problems
  - QuerySet annotations eliminate redundant queries 