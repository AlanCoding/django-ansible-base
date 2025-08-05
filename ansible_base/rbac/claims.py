import hashlib
import json
from collections import defaultdict
from typing import Union

from django.apps import apps
from django.conf import settings
from django.db.models import F, Model, OuterRef, QuerySet

from ansible_base.lib.utils.auth import get_team_model

from .models.content_type import DABContentType
from .models.role import RoleDefinition


def get_user_object_roles(user: Model) -> QuerySet:
    """Get all object-scoped role assignments for a user with resource metadata.

    This function retrieves role assignments that are scoped to specific objects
    (not global roles) and joins them with resource registry data to include
    ansible_id and name values. Only JWT-managed roles are included.

    Args:
        user: Django user model instance

    Returns:
        QuerySet of role assignments annotated with:
        - aid: ansible_id from the resource registry
        - resource_name: name from the resource registry
        - rd_name: role definition name
        - content_type_id: Integer ID of the content type for the assigned object

    The queryset is filtered to:
        - Object-scoped assignments only (content_type is not null)
        - JWT-managed roles only (as defined in settings)

    Example usage:
        assignments = get_user_object_roles(user)
        for assignment in assignments:
            print(assignment.rd_name, assignment.aid, assignment.resource_name, assignment.content_type_id)
    """
    # Create subqueries for resource data
    resource_cls = apps.get_model('dab_resource_registry', 'Resource')
    ansible_id_subquery = resource_cls.objects.filter(object_id=OuterRef('object_id'), content_type=OuterRef('content_type')).values('ansible_id')

    resource_name_subquery = resource_cls.objects.filter(object_id=OuterRef('object_id'), content_type=OuterRef('content_type')).values('name')

    return (
        user.role_assignments.filter(content_type__isnull=False)
        .annotate(aid=ansible_id_subquery, resource_name=resource_name_subquery, rd_name=F('role_definition__name'))
        .filter(rd_name__in=settings.ANSIBLE_BASE_JWT_MANAGED_ROLES)
    )


def _resolve_team_organization_references(
    object_arrays: dict[str, list],
    org_ansible_id_to_index: dict[str, int],
) -> None:
    """Resolve team organization references by converting ansible_ids to array positions.

    This method queries the team model to get organization mappings for teams,
    then updates team objects to reference their organizations by array position
    instead of ansible_id. If a team's organization is not already in the object
    arrays, it will be added.

    Args:
        object_arrays: Dictionary with model_type -> list of objects (will be modified)
        org_ansible_id_to_index: Maps organization ansible_id -> array_position (will be modified)

    The method modifies object_arrays and org_ansible_id_to_index in place:
    - Updates team objects' 'org' field from ansible_id to array position
    - Adds missing organizations to object_arrays['organization'] if needed
    - Updates org_ansible_id_to_index mappings for any added organizations
    """
    # Extract team ansible_ids from the team objects
    team_ansible_ids = {team_data['ansible_id'] for team_data in object_arrays['team']}

    if not team_ansible_ids:
        return

    # Query team model to get team -> organization mappings with organization names
    team_cls = get_team_model()
    team_org_mapping = {}
    for team in team_cls.objects.filter(resource__ansible_id__in=team_ansible_ids).values(
        'resource__ansible_id', 'organization__resource__ansible_id', 'organization__name'
    ):
        team_ansible_id = str(team['resource__ansible_id'])
        org_ansible_id = str(team['organization__resource__ansible_id'])
        org_name = team['organization__name']
        team_org_mapping[team_ansible_id] = {'ansible_id': org_ansible_id, 'name': org_name}

    # Update team objects with organization references
    for team_data in object_arrays['team']:
        team_ansible_id = team_data['ansible_id']
        org_info = team_org_mapping.get(team_ansible_id)

        if org_info:
            org_ansible_id = org_info['ansible_id']
            org_name = org_info['name']

            # Ensure the organization is in our arrays
            if org_ansible_id not in org_ansible_id_to_index:
                # Add missing organization using data from the query
                if 'organization' not in object_arrays:
                    object_arrays['organization'] = []
                org_index = len(object_arrays['organization'])
                org_ansible_id_to_index[org_ansible_id] = org_index
                org_data = {'ansible_id': org_ansible_id, 'name': org_name}
                object_arrays['organization'].append(org_data)

            # Set the organization reference to the array position
            team_data['org'] = org_ansible_id_to_index[org_ansible_id]


def _build_objects_and_roles(
    user: Model,
) -> tuple[dict[str, list], dict[str, dict[str, Union[str, list[int]]]]]:
    """Process user's object-scoped role assignments and return objects and roles data.

    Args:
        user: User model instance

    Returns:
        Tuple containing:
        - object_arrays: Dictionary with model_type -> list of objects
        - object_roles: Dictionary mapping role names to role data

    Example:
        (
            {'organization': [{'ansible_id': 'uuid1', 'name': 'Org1'}], 'team': []},
            {'Organization Admin': {'content_type': 'organization', 'objects': [0]}}
        )
    """
    # Initialize empty object arrays and roles with expected keys
    object_arrays = {'organization': [], 'team': []}
    object_roles = {}

    # Internal tracking for ansible_id to array position mapping
    ansible_id_to_index = defaultdict(dict)  # { <model_type>: {<ansible_id>: <array_position> } }

    # Single loop: build object_arrays and object_roles
    for assignment in get_user_object_roles(user):
        role_name = assignment.rd_name
        ansible_id = str(assignment.aid)
        resource_name = str(assignment.resource_name)
        content_type_id = assignment.content_type_id
        model_type = DABContentType.objects.get_for_id(content_type_id).model

        # Ensure the model_type exists in object_arrays (for non-standard types)
        if model_type not in object_arrays:
            object_arrays[model_type] = []

        # If the ansible_id is not yet indexed
        if ansible_id not in ansible_id_to_index[model_type]:
            # Cache the array position (current len will be the next index when we append)
            ansible_id_to_index[model_type][ansible_id] = len(object_arrays[model_type])
            # Add the object to the array
            object_data = {'ansible_id': ansible_id, 'name': resource_name}
            object_arrays[model_type].append(object_data)

        # Get the array position from the cache
        array_position = ansible_id_to_index[model_type][ansible_id]

        # If the role is not in object_roles, initialize it
        if role_name not in object_roles:
            object_roles[role_name] = {'content_type': model_type, 'objects': []}

        # Add the array position to the role
        object_roles[role_name]['objects'].append(array_position)

    # Resolve team organization references
    _resolve_team_organization_references(object_arrays, ansible_id_to_index['organization'])

    return object_arrays, object_roles


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
    # Warm the DABContentType cache for efficient lookups
    DABContentType.objects.warm_cache()

    # Build object arrays and roles from user's assignments
    object_arrays, object_roles = _build_objects_and_roles(user)

    # Get global roles
    global_roles = _get_user_global_roles(user)

    # Build final claims structure
    return {'objects': object_arrays, 'object_roles': object_roles, 'global_roles': global_roles}


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
