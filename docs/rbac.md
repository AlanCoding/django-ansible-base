# Role-Based Access Control (RBAC)

This documents the Role Based Access Control (RBAC) implementation.
This intended for a developer audience.

This is derived from the RBAC system in AWX which was implemented roughly
in the year 2015, and this remained stable until an overhaul, with early work
proceeding in the year 2023.

## Using

Start with `docs/Installation.md` for the core ansible_base setup.

### RBAC Usage at ORM layer

Developers should interact with the `RoleDefinition` as an ordinary model.
Ordinarily, the `ObjectRole` or `RoleEvaluation` should not be interacted with.

#### Creating a New Role Definition

These are expected to be user-defined in many apps.
Example of creating a custom role definition:

```
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from awx.ansible_base.models.rbac import RoleDefinition

# Create a new custom RoleDefinition
jt_ct = ContentType.objects.get_for_model(JobTemplate)
rd = RoleDefinition.objects.get_or_create(
  name='all-job-template-permissions',
  permissions=list(Permission.objects.filter(content_type=jt_ct))
)
```

#### Giving User Role to Object

Using the role definition from the last code block, give a user that role to
an object using the `give_permission` method.

```
from awx.main.models import JobTemplate

# Give permissions of the RoleDefinition to a user for an object
jt = JobTemplate.objects.get(name='Demo Job Template')
u = User.objects.get(username='alan')
rd.give_permission(u, jt)
```

This would give the user "alan" all allowed permission types to the Demo JT.
You can reverse this action with the `remove_permission` method.

Both methods will return an `ObjectRole` as a result.
The object roles are managed by the RBAC system, and created or deleted as needed.
The object role maps a role definition to an object, and has a related association
for users and teams who have that object role.

#### Registering Models

Any Django Model can
be made into a resource in the RBAC system by registering that resource in the registry.

```
from awx.ansible_base.utils.permission_registry import permission_registry

permission_registry.register(MyModel)
```

The Django auth app already creates permissions in a migration.
If you need to manage special permissions beyond the default permissions, these need to
be added in the model's `Meta` according to the Django documentation.

#### Creator Permissions

You can give a user add permission to an organization, like "add_mymodel".
The Django `Permission` entry will link to `MyModel` but inside of roles,
these permissions only apply to the parent model of the object,
or act as singleton roles.

After the object is created, you need to give the user creator permissions.
Otherwise they won't even to be able to see what they created!

```
RoleDefinition.objects.give_creator_permissions(u, jt)
```

This will assign all valid permissions for the object they created from the
list in `settings.ROLE_CREATOR_DEFAULTS`.

### Django Settings for RBAC

You can specify which model you want to use for Organization / User / Team models.
The user model is obtained from the generic Django user setup, like the `AUTH_USER_MODEL` setting.

CAUTION: these settings will be used in _migrations_ so if you change these
settings later on, you will need to handle that in a new migration.

```
ROLE_TEAM_MODEL = 'auth.Group'
ROLE_ORGANIZATION_MODEL = 'main.Organization'
```

You don't strictly need an organization model (the setting is only used
for role pre-created roles), but a core feature of this
system is maintaining a resource hierarchy. Organization is just an assumed
root model for resources. You could use any model for as parent resources
or have multiple hierarchies.

#### Creator Permissions

If a user has `add` permission to a resource, they should get permissions
to the object they created. Specify those with this setting.

```
ROLE_CREATOR_DEFAULTS = ['change', 'delete', 'view']
```

#### Managed Pre-Created Role Definitions

In a post_migrate signal, certain RoleDefinitions are pre-created.
You can customize that with the following setting.

```
GATEWAY_ROLE_PRECREATE = {
    'object_admin': '{cls._meta.model_name}-admin',
    'org_admin': 'organization-admin',
    'org_children': 'organization-{cls._meta.model_name}-admin',
    'special': '{cls._meta.model_name}-{action}',
}
```

Set this to `{}` if you will create role definitions in your own data migration,
or if you want all roles to be user-defined.

#### RBAC vs User Flag Responsibilities

With some user flags, like the standard `is_superuser` flag, the RBAC system does not
need to be consulted to make an evaluation.
You may or may not want this to be done as part of the attached methods
like `accessible_objects` or `has_obj_perm`. That can be controlled with these.

```
ROLE_BYPASS_SUPERUSER_FLAGS = ['is_superuser']
ROLE_BYPASS_ACTION_FLAGS = {'view': 'is_system_auditor'}
```

You can blank these with values `[]` and `{}`. In these cases, the querysets
will produce nothing for the superuser if they have not been assigned any roles.

### RBAC - System Basics

Users can be members of an object role, which gives them the listed permissions to the
resource associated with that object role, or any child resources of
that object.

For example, if I have an organization named "MyCompany" and I want to allow
two people, "Alice", and "Bob", access to manage all of the settings associated
with that organization, I'd make them both members of the organization's
object role corresponding to the "organization-admin" role definition.

The 2015 implementation had these key features:
 - object roles were auto-created when a resource was created
 - roles formed an acyclic (or cyclic) graph between each other via their parents and children
 - object roles were defined by the `ImplicitRoleField` declared on each model
 - teams gain permission by adding their `member_role` to parents of another role

The key features and differences of the 2023 system are:
 - object roles are not auto-created, but only created as needed to perform assignments
 - resources are organized in a strict tree, mostly with organizations being the parents
 - role definitions list canonical Django Permission objects
 - teams are listed in a `role.teams.all()` relationship directly, similar to users

### Implementation Overview

If the model has an `organization` field, then this assumed to be the parent object.
Custom parent objects are still not implemented.

### Parent Object Permissions

An object role has a role definition with permissions, like `execute_jobtemplate`.
A user having that role will have the ability to launch the job template.
A user can gain that permission through a number of other roles that offer a form of inheritance.

A job template, like other resources, is considered to be in an organization.
If you give someone an object role associated with the job template's organization,
and that role's permissions list `execute_jobtemplate`, they will obtain the ability
to launch that job template along with all other job templates in the organization.

### Models

The RBAC system defines a few new models. These models represent the underlying RBAC implementation and generally will be abstracted away from your daily development tasks by signals connected by the permission registry.

#### `ObjectRole`

`ObjectRole` defines a single role with an object association within the RBAC implementation.

##### `descendent_roles()`

For a given object role, if that role offers a "member_team" permission, this gives all
the roles that are implied by ownership of this role.

For object roles that do not offer that permission, or do not apply to a team
or a team's parent objects, this should return an empty set.

##### `needed_cache_updates()`

This shows the additions and removals needed to make the `RoleEvaluation` correct
for the particular `ObjectRole` in question.
This is used as a part of the re-computation logic to cache role-object-permission evaluations.

#### `RoleEvaluation`

`RoleEvaluation` gives cached permission evaluations for a role.
Each entry tells you that ownership in the linked `role` field confers the
permission listed in the `codename` field to the object defined by the
fields `object_id` and `content_type_id`.

This is used for generating querysets and making role evaluations.

This table is _not_ the source of truth for information in any way.
You can delete the entire table, and you should be able to re-populate it
by calling the `compute_object_role_permissions()` method.

Because its function is querysets and permission evaluations, it has
class methods that serve these functions.
Importantly, these consider _indirect_ permissions given by parent objects,
teams, or both.

##### `accessible_ids(cls, user, codename)`

Returns a queryset which is a values list of ids for objects of `cls` type
that `user` has the permission to, where that permission is given in `codename`.

This is lighter weight and more efficient than using `accessible_objects` when it is needed
as a subquery as a part of a larger query.

##### `accessible_objects(cls, user, codename)`

Return a queryset from `cls` model that `user` has the `codename` permission to.

##### `get_permissions(user, obj)`

Returns all permissions that `user` has to `obj`.

### Attached Methods

Several methods are attached to any model registered via `permission_registry`.
For example, you could do `MyModel.accessible_objects(user, 'change_mymodel')`
to get a queryset of `MyModel` that the `user` has change permission to.
