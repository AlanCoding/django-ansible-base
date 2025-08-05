# Claims Hashing Test Plan

## Test Strategy

The claims hashing system must be thoroughly tested to ensure deterministic, secure, and reliable operation. Tests must verify that hashes are stable across various scenarios while being sensitive to actual permission changes.

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

### 2. Determinism Tests

#### Test: Same Permissions, Same Hash
- **Objective**: Identical permission sets produce identical hashes
- **Setup**: 
  - Create 2 users with identical permissions
  - Same organizations, teams, roles
- **Verification**: Both users produce identical hash

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
- **Verification**: Hash remains constant across queries

#### Test: Removal and Re-addition
- **Objective**: Removing and re-adding same permission produces same hash
- **Setup**:
  1. User with org admin permission
  2. Record hash
  3. Remove org admin permission  
  4. Re-add same org admin permission
- **Verification**: Final hash matches original hash

### 3. Immutability Tests

#### Test: Object Rename Stability
- **Objective**: Renaming objects doesn't change hash
- **Setup**:
  1. User with org admin permission on "Engineering Org"
  2. Record hash
  3. Rename organization to "Development Org"
- **Verification**: Hash remains unchanged

#### Test: Object Move Stability
- **Objective**: Moving teams between orgs updates hash correctly
- **Setup**:
  1. User with team member permission on team in org1
  2. Record hash  
  3. Move team to org2
- **Verification**: Hash changes (org reference changed in team object)

#### Test: Ansible ID Stability
- **Objective**: Hash based on ansible_id, not database ID
- **Setup**:
  1. Create user with permissions
  2. Record hash
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