import hashlib
import json
from typing import Type, Union

from django.apps import apps
from django.conf import settings
from django.db.models import F, Model, OuterRef, QuerySet

from ansible_base.lib.utils.auth import get_organization_model, get_team_model

from .models.content_type import DABContentType
from .models.role import RoleDefinition


def _get_resource_model() -> Type[Model]:
    """Get the Resource model class from the resource registry.

    Returns:
        The Resource model class used for ansible_id lookups
    """
    return apps.get_model('dab_resource_registry', 'Resource')


def _build_resource_subquery() -> QuerySet:
    """Build a subquery to retrieve ansible_id values for resources.

    This subquery is used to annotate role assignments with their corresponding
    ansible_id values from the resource registry.

    Returns:
        QuerySet that filters resources by object_id and content_type from outer query
        and returns ansible_id values
    """
    resource_cls = _get_resource_model()
    return resource_cls.objects.filter(object_id=OuterRef('object_id'), content_type=OuterRef('content_type')).values('ansible_id')


def _build_role_assignments_queryset(user: Model, resource_subquery: QuerySet) -> QuerySet:
    """Build queryset of role assignments with ansible_id and role name annotations.

    Args:
        user: The user whose role assignments to query
        resource_subquery: Subquery to get ansible_id values

    Returns:
        QuerySet of role assignments filtered to:
        - Object-scoped assignments only (content_type is not null)
        - JWT-managed roles only (as defined in settings)
        Annotated with:
        - aid: ansible_id from the resource registry
        - rd_name: role definition name
    """
    return (
        user.role_assignments.filter(content_type__isnull=False)
        .annotate(aid=resource_subquery, rd_name=F('role_definition__name'))
        .filter(rd_name__in=settings.ANSIBLE_BASE_JWT_MANAGED_ROLES)
    )


def _format_role_assignment_results(assignment_queryset: QuerySet) -> list[tuple[str, str, int]]:
    """Convert role assignment queryset to list of tuples.

    Args:
        assignment_queryset: QuerySet with aid and rd_name annotations

    Returns:
        List of tuples containing (role_name, ansible_id, content_type_id)
        where:
        - role_name: Name of the role definition (e.g., "Organization Admin")
        - ansible_id: String representation of the resource's ansible_id
        - content_type_id: Integer ID of the content type
    """
    return [(ra.rd_name, str(ra.aid), ra.content_type_id) for ra in assignment_queryset]


def get_user_object_roles(user: Model) -> list[tuple[str, str, int]]:
    """Get all object-scoped role assignments for a user with resource metadata.

    This function retrieves role assignments that are scoped to specific objects
    (not global roles) and joins them with resource registry data to include
    ansible_id values. Only JWT-managed roles are included.

    Args:
        user: Django user model instance

    Returns:
        List of tuples containing (role_name, ansible_id, content_type_id):
        - role_name: Name of the role definition (e.g., "Organization Admin")
        - ansible_id: String representation of the resource's ansible_id
        - content_type_id: Integer ID of the content type for the assigned object

    Example:
        [
            ("Organization Admin", "uuid-123", 42),
            ("Team Member", "uuid-456", 43)
        ]
    """
    resource_subquery = _build_resource_subquery()
    assignment_queryset = _build_role_assignments_queryset(user, resource_subquery)
    return _format_role_assignment_results(assignment_queryset)


def _build_organization_data(org_cls: Type[Model], claims: dict, required_data: dict[str, dict]) -> str:
    """Build organization data for claims processing.

    Args:
        org_cls: Organization model class
        claims: Claims dictionary to populate
        required_data: Required data cache to populate

    Returns:
        String representing the organization content type model name
    """
    org_content_type_model = DABContentType.objects.get_for_model(org_cls).model
    required_data[org_content_type_model] = {}

    # Populate required_data for organizations
    for org in org_cls.objects.all().values('id', 'name', 'resource__ansible_id'):
        org_id = org['id']
        name = org['name']
        ansible_id = str(org['resource__ansible_id'])
        org_data = {'ansible_id': ansible_id, 'name': name}

        # Store by both id and ansible_id for flexible lookup
        required_data[org_content_type_model][org_id] = org_data
        required_data[org_content_type_model][ansible_id] = org_data

    claims['objects'][org_content_type_model] = []
    return org_content_type_model


def _build_team_data(team_cls: Type[Model], claims: dict, required_data: dict[str, dict]) -> str:
    """Build team data for claims processing.

    Args:
        team_cls: Team model class
        claims: Claims dictionary to populate
        required_data: Required data cache to populate

    Returns:
        String representing the team content type model name
    """
    team_content_type_model = DABContentType.objects.get_for_model(team_cls).model
    required_data[team_content_type_model] = {}

    # Populate required_data for teams
    for team in team_cls.objects.all().values('id', 'name', 'resource__ansible_id', 'organization__resource__ansible_id'):
        team_id = team['id']
        team_name = team['name']
        ansible_id = str(team['resource__ansible_id'])
        related_org_ansible_id = str(team['organization__resource__ansible_id'])
        team_data = {'ansible_id': ansible_id, 'name': team_name, 'org': related_org_ansible_id}

        # Store by both id and ansible_id for flexible lookup
        required_data[team_content_type_model][team_id] = team_data
        required_data[team_content_type_model][ansible_id] = team_data

    claims['objects'][team_content_type_model] = []
    return team_content_type_model


def _process_user_object_roles(
    user: Model,
    org_content_type_model: str,
    team_content_type_model: str,
    cached_objects_index: dict[str, dict],
    cached_content_types: dict[int, str],
    required_data: dict[str, dict],
) -> tuple[dict[str, list], dict[str, dict[str, Union[str, list[int]]]]]:
    """Process user's object-scoped role assignments and return objects and roles data.

    Args:
        user: User model instance
        org_content_type_model: String name of organization content type model
        team_content_type_model: String name of team content type model
        cached_objects_index: Cache mapping content_model -> ansible_id -> array_index (will be modified)
        cached_content_types: Cache mapping content_type_id -> model_name
        required_data: Cache containing object data by content_model and ansible_id

    Returns:
        Tuple containing:
        - objects_dict: Dictionary with content_model -> list of objects
        - object_roles: Dictionary mapping role names to role data

    Example:
        (
            {'organization': [{'ansible_id': 'uuid1', 'name': 'Org1'}], 'team': []},
            {'Organization Admin': {'content_type': 'organization', 'objects': [0]}}
        )
    """
    # Initialize objects dict with empty arrays
    objects_dict = {org_content_type_model: [], team_content_type_model: []}

    user_object_roles = get_user_object_roles(user)
    object_roles = {}

    for role_name, ansible_id, content_type_id in user_object_roles:
        # Get the model for this content_type
        content_model_type = cached_content_types[content_type_id]

        # If the ansible_id is not in the cached_objects_index
        if ansible_id not in cached_objects_index[content_model_type]:
            # Cache the index (current len will be the next index when we append)
            cached_objects_index[content_model_type][ansible_id] = len(objects_dict[content_model_type])
            # Add the object to the objects dict
            objects_dict[content_model_type].append(required_data[content_model_type][ansible_id])

        # Get the index value from the cache
        object_index = cached_objects_index[content_model_type][ansible_id]

        # If the role is not in object_roles, initialize it
        if role_name not in object_roles:
            object_roles[role_name] = {'content_type': content_model_type, 'objects': []}

        # Add the object index to the role
        object_roles[role_name]['objects'].append(object_index)

    return objects_dict, object_roles


def _fix_team_organization_references(
    objects_dict: dict[str, list],
    team_content_type_model: str,
    org_content_type_model: str,
    cached_objects_index: dict[str, dict],
    required_data: dict[str, dict],
) -> None:
    """Convert team organization references from ansible_ids to array indexes.

    Teams initially reference their organizations by ansible_id. This method
    converts those references to array indexes within the objects structure.

    Args:
        objects_dict: Dictionary with content_model -> list of objects (will be modified)
        team_content_type_model: String name of team content type model
        org_content_type_model: String name of organization content type model
        cached_objects_index: Cache mapping content_model -> ansible_id -> array_index (will be modified)
        required_data: Cache containing object data by content_model and ansible_id
    """
    for team in objects_dict[team_content_type_model]:
        org_ansible_id = team['org']

        if org_ansible_id in cached_objects_index[org_content_type_model]:
            # Organization is already in objects, use its index
            team['org'] = cached_objects_index[org_content_type_model][org_ansible_id]
        else:
            # Organization not yet in objects - add it
            org_index = len(objects_dict[org_content_type_model])
            cached_objects_index[org_content_type_model][org_ansible_id] = org_index
            org_data = required_data[org_content_type_model][org_ansible_id]
            team['org'] = org_index
            objects_dict[org_content_type_model].append(org_data)


def _get_user_global_roles(user: Model) -> list[str]:
    """Get user's global role assignments.

    Args:
        user: User model instance

    Returns:
        List of global role names assigned to the user

    Example:
        ['Platform Auditor', 'System Administrator']
    """
    global_roles_query = RoleDefinition.objects.filter(content_type=None, user_assignments__user=user.pk, name__in=settings.ANSIBLE_BASE_JWT_MANAGED_ROLES)

    return [role_definition.name for role_definition in global_roles_query]


def get_user_claims(user: Model) -> dict[str, Union[list[str], dict[str, Union[str, list[dict[str, str]]]]]]:
    """Generate comprehensive claims data for a user including roles and object access.

    This function builds a complete picture of a user's permissions by gathering:
    - Global roles (system-wide permissions)
    - Object roles (permissions on specific resources)
    - Object metadata (organizations and teams the user has access to)

    Args:
        user: Django user model instance

    Returns:
        Dictionary containing:
        - objects: Nested dict with arrays of organization/team objects user has access to
        - object_roles: Dict mapping role names to content types and object indexes
        - global_roles: List of global role names assigned to the user

    Example:
        {
            'objects': {
                'organization': [{'ansible_id': 'uuid1', 'name': 'Org1'}],
                'team': [{'ansible_id': 'uuid2', 'name': 'Team1', 'org': 0}]
            },
            'object_roles': {
                'Organization Admin': {'content_type': 'organization', 'objects': [0]}
            },
            'global_roles': ['Platform Auditor']
        }
    """
    # Initialize caching dictionaries
    cached_objects_index = {}  # { <content_model>: {<ansible_id>: <array index integer> } }
    cached_content_types = {}  # { <content id integer>: <content_model> }
    required_data = {}  # { <content_model>: { <ansible_id>|<id>: <required_data> } }

    # Build content type caches
    for content_type in DABContentType.objects.all().values('id', 'model'):
        content_type_id = content_type['id']
        model = content_type['model']
        cached_content_types[content_type_id] = model
        cached_objects_index[model] = {}

    # Get model classes
    org_cls = get_organization_model()
    team_cls = get_team_model()

    # Build organization and team data caches
    org_content_type_model = _build_organization_data(org_cls, {'objects': {}}, required_data)
    team_content_type_model = _build_team_data(team_cls, {'objects': {}}, required_data)

    # Process user's object role assignments
    objects_dict, object_roles = _process_user_object_roles(
        user, org_content_type_model, team_content_type_model, cached_objects_index, cached_content_types, required_data
    )

    # Convert team organization references from ansible_ids to indexes
    _fix_team_organization_references(objects_dict, team_content_type_model, org_content_type_model, cached_objects_index, required_data)

    # Get global roles
    global_roles = _get_user_global_roles(user)

    # Build final claims structure
    return {'objects': objects_dict, 'object_roles': object_roles, 'global_roles': global_roles}


def get_user_claims_hashable_form(claims: dict) -> dict[str, Union[list[str], dict[str, list[str]]]]:
    """Convert user claims to hashable form suitable for generating deterministic hashes.

    Args:
        claims: Claims dictionary from get_user_claims()

    The hashable form:
    - Removes the 'objects' section entirely
    - Converts object role references from array indexes to ansible_id values
    - Sorts all collections for deterministic ordering
    - Uses ansible_id for object references (or id if no ansible_id, for future use)

    Returns:
        {
            'global_roles': ['Platform Auditor', 'System Admin'],  # sorted
            'object_roles': {
                'Organization Admin': ['uuid1', 'uuid2'],  # sorted ansible_ids
                'Team Member': ['uuid3', 'uuid4']         # sorted ansible_ids
            }
        }
    """

    hashable_claims = {'global_roles': sorted(claims['global_roles']), 'object_roles': {}}

    # Convert object_roles from indexes to ansible_ids
    for role_name, role_data in claims['object_roles'].items():
        content_type = role_data['content_type']
        object_indexes = role_data['objects']

        # Get the objects array for this content type
        objects_array = claims['objects'].get(content_type, [])

        # Convert indexes to ansible_ids
        ansible_ids = []
        for index in object_indexes:
            if index < len(objects_array):
                obj_data = objects_array[index]
                # Use ansible_id if available, otherwise fall back to id (for future use)
                ansible_id = obj_data.get('ansible_id') or str(obj_data.get('id', ''))
                if ansible_id:
                    ansible_ids.append(ansible_id)

        # Sort ansible_ids for deterministic ordering
        hashable_claims['object_roles'][role_name] = sorted(ansible_ids)

    return hashable_claims


def get_claims_hash(hashable_claims: dict) -> str:
    """Generate a deterministic SHA-256 hash from hashable claims data.

    Args:
        hashable_claims: Output from get_user_claims_hashable_form()

    Returns:
        64-character hex string representing the SHA-256 hash of the claims

    The hash is generated by:
    1. Serializing the hashable claims to JSON with sorted keys
    2. Encoding to UTF-8 bytes
    3. Computing SHA-256 hash
    4. Returning as hexadecimal string
    """
    # Serialize to JSON with sorted keys for deterministic output
    json_str = json.dumps(hashable_claims, sort_keys=True, separators=(',', ':'))

    # Encode to bytes and compute SHA-256 hash
    json_bytes = json_str.encode('utf-8')
    hash_digest = hashlib.sha256(json_bytes).hexdigest()

    return hash_digest
