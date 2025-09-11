## Using DAB RBAC as an API Client

This section explains how to use the RBAC API endpoints to manage permissions. The API follows a clear hierarchy that reflects the system architecture.

### Prerequisites

You need a server running a Django project that uses DAB RBAC.
Use test_app in this repo for a demo (see `test_app/README.md` for setup).
The server runs at http://127.0.0.1:8000, and examples reference this base URL.
Default admin password is "admin".

### API Workflow Overview

The RBAC API follows standard REST practices where models have relational dependencies. The typical order for establishing permissions:

1. **Types** (`/api/v1/role_metadata/`) - Read-only, managed by app developers
2. **Permissions** - Read-only, created when models are registered
3. **Role Definitions** (`/api/v1/role_definitions/`) - Managed and custom roles
4. **Role Assignments** - User assignments (`/api/v1/role_user_assignments/`) and team assignments (`/api/v1/role_team_assignments/`)

Users interact primarily with steps 3 and 4, while steps 1 and 2 are controlled by the application configuration.

## Step 1: Understanding Available Types and Permissions

### View Available Content Types

Get the available content types and their permissions:

```
GET /api/v1/role_metadata/
```

This returns read-only information configured by app developers:
- Available content types (e.g., "aap.inventory", "shared.organization")
- Permissions allowed for each content type
- No user interaction required with this data

## Step 2: Creating Role Definitions

### Create a Custom Role Definition

```
POST /api/v1/role_definitions/
```

Example request body:

```json
{
    "permissions": ["view_inventory"],
    "content_type": "aap.inventory",
    "name": "View a single inventory",
    "description": "Custom role for inventory viewing"
}
```

Required fields:
- `permissions`: List of permission codenames (from step 1)
- `content_type`: Content type string (from step 1)
- `name`: Display name for the role definition

Optional fields:
- `description`: Additional context about the role definition

### Managed vs Custom Role Definitions

- **Managed roles**: Created by app developers, cannot be modified via API
- **Custom roles**: Created by users, fully manageable via API

## Step 3: User Role Assignments

### Assign Role Definition to User for Object

Once you have a role definition, assign it to a user for a specific object:

```
POST /api/v1/role_user_assignments/
```

Example request body:

```json
{
    "role_definition": 3,
    "object_id": 3,
    "user": 3
}
```

Required fields:
- `role_definition`: ID from `/api/v1/role_definitions/`
- `user`: ID from `/api/v1/users/`
- `object_id`: ID of the target object (e.g., from `/api/v1/inventories/`)

This grants the user the role definition's permissions for only the specified object.

### Assign Role Definition to User Globally

For system-wide permissions, omit the `object_id`:

```json
{
    "role_definition": 5,
    "user": 3
}
```

The role definition must have `content_type: null` for global assignments.

## Step 4: Team Role Assignments

### Team Membership

First, users must be members of teams. Team membership grants the "member_team" permission and automatically inherits all permissions assigned to the team.

### Assign Role Definition to Team

```
POST /api/v1/role_team_assignments/
```

Example request body:

```json
{
    "role_definition": 3,
    "object_id": 3,
    "team": 2
}
```

This grants the role definition's permissions to all members of the team for the specified object.

## Management Operations

### View Existing Assignments

List assignments for a specific object:

```
GET /api/v1/role_user_assignments/?object_id=3&content_type__model=inventory
GET /api/v1/role_team_assignments/?object_id=3&content_type__model=inventory
```

### Revoke an Assignment

Delete a specific assignment by ID:

```
DELETE /api/v1/role_user_assignments/1/
```

This removes the assignment and all permissions it granted.

## Organization-Level Permissions

### Assigning Organization-Wide Permissions

To grant permissions to all objects within an organization:

1. **Create an organization-level role definition:**
   ```json
   {
       "permissions": ["view_inventory", "change_inventory"],
       "content_type": "shared.organization",
       "name": "Organization Inventory Manager"
   }
   ```

2. **Assign to user/team using organization ID:**
   ```json
   {
       "role_definition": 4,
       "object_id": 1,  // organization ID
       "user": 3
   }
   ```

This grants the specified permissions to all inventories within organization ID 1.

## Error Handling

Common API errors:
- **400 Bad Request**: Invalid role definition/object/user combination
- **403 Forbidden**: Insufficient permissions to create assignment (you need "change" permission to the object to create role assignments)
- **404 Not Found**: Referenced object does not exist
