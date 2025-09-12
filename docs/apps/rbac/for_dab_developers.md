## DAB RBAC System Design Principles

The DAB RBAC features and goals:
 - Adheres to patterns created by django.contrib.auth, specifically its permission model
 - Adds roles, containers of multiple permissions
 - Adds teams, allowing bulk-assignment of permissions to a group of users
 - Allows managing multiple "levels" of permissions
   - object-level permission
   - inheritance from an objects parent object, main organization
   - system-wide permissions
 - Be as lazy as possible

This is a combination of former galaxy_ng/pulp and AWX systems.
The galaxy_ng/pulp RBAC system had everything above except for inheritance.
The AWX system did not enumerate permissions at all, and structured roles in a graph-based design.

### Internal Terminology

For DAB developers working on the RBAC system itself:

- **Role Definition** - Always use this term; never "role" which is ambiguous
- **Object Role** - Instantiation of a role definition for a specific object
- **Role Assignment** - Record of user/team having a role definition (user assignment or team assignment)
- **Permission** - Django Permission object representing an action on a model type
- **Access** - Discouraged term; use specific permission checks instead
- **Content Type** - Use DABContentType, not Django's ContentType

### Evolution from Role Graphs to Resource Trees

**Previous (2015) AWX System:**
The older system created a complex graph where roles had parent-child relationships with other roles. Each object auto-created its own roles, and permissions flowed through role inheritance chains. This means you could have "admin_role" to a job template which would give CRUD permissions plus the ability to run the job template, or "execute_role" which would give ability to run but not the ability to edit. Inheritance worked by "admin_role" to an organization being a parent of the roles of all objects within the organization.

**Current (2023+) System:**
The current system abandons role-to-role inheritance in favor of:
- **Resource Tree Structure**: Resources are organized in a strict hierarchical tree (typically with organizations as parents)
- **Named Permissions**: Instead of role inheritance, we use explicit Django Permission objects
- **On-Demand Object Roles**: Object roles are only created when assignments are made, not automatically
- **Direct Relationships**: Teams and users have direct relationships to role definitions

### Key Architectural Components

#### Resource Hierarchy (Not Role Hierarchy)
Resources form a tree where parent-child relationships are defined by the models themselves (e.g., inventories belong to organizations). Permission inheritance flows down this resource tree, not through a separate role graph.

#### Named Permissions Replace Role Inheritance
Instead of roles inheriting from other roles, we explicitly list Django Permission objects in role definitions. This makes permission grants more transparent and predictable.

#### Team Membership as Permission Multiplication
Teams can have member permissions to other teams, but this is the only remaining "graph-like" structure. This is intentionally limited to team membership to keep complexity manageable.

### Performance Through Caching

Both the old and current systems use Django signals to cache permission evaluations. The `RoleEvaluation` table caches which users have which permissions to which objects, enabling efficient queryset filtering without performance degradation.

#### System-Wide vs Object-Specific Roles
System-wide roles are handled through a separate, lighter-weight system that doesn't require the same caching overhead as object-specific roles. This allows for more flexible global permission management.

## Models

These models represent the underlying RBAC implementation and are generally abstracted away from daily development tasks by signals connected through the permission registry.

### `ObjectRole`

`ObjectRole` represents an instantiation of a role definition for a particular object. Object roles are created on-demand when assignments are made, rather than being auto-created for every resource.

Key characteristics:
- Links a role definition to a specific object
- Created by `give_permission` methods when assignments are made
- Handles team membership inheritance through `descendent_roles()`
- Manages cache updates for efficient permission evaluation

### `RoleEvaluation`

`RoleEvaluation` provides cached permission evaluations for efficient querying. This is a performance optimization table that can be completely rebuilt from the source data.

Key characteristics:
- Caches which users/teams have which permissions to which objects
- Not the source of truth - can be deleted and regenerated
- Enables efficient queryset filtering through class methods
- Handles indirect permissions (parent objects, team inheritance)

## Integration with App Models

For application developers using DAB RBAC, the system attaches methods directly to your registered models. These methods provide the primary interface for permission evaluation:

- `MyModel.access_qs(user, permission)` - Filter querysets by permission
- `user.has_obj_perm(obj, permission)` - Check specific object permissions

For detailed documentation on these methods and their usage patterns, see the [App Developer Integration Guide](for_app_developers.md#evaluating-permissions).
