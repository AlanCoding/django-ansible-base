from typing import Union

from django.apps import apps
from django.conf import settings
from django.db.models import F, Model, OuterRef

from ansible_base.lib.utils.auth import get_organization_model, get_team_model

from .models.content_type import DABContentType
from .models.role import RoleDefinition


def get_user_object_roles(user: Model) -> list[tuple[str, str, int]]:
    """Returns a list of tuples giving (role name, ansible_id, content_type_id)

    This data is the role name joined with data about the resource"""
    resource_cls = apps.get_model('dab_resource_registry', 'Resource')
    resource_qs = resource_cls.objects.filter(object_id=OuterRef('object_id'), content_type=OuterRef('content_type')).values('ansible_id')
    assignment_qs = (
        user.role_assignments.filter(content_type__isnull=False)
        .annotate(aid=resource_qs, rd_name=F('role_definition__name'))
        .filter(rd_name__in=settings.ANSIBLE_BASE_JWT_MANAGED_ROLES)
    )
    return [(ra.rd_name, str(ra.aid), ra.content_type_id) for ra in assignment_qs]


def get_user_claims(user: Model) -> dict[str, Union[list[str], dict[str, Union[str, list[dict[str, str]]]]]]:
    claims = {'objects': {}, 'object_roles': {}, 'global_roles': []}

    org_cls = get_organization_model()
    team_cls = get_team_model()

    cached_objects_index = {}  # Entries like { <content_model>: {<ansible_id>: <array index integer> } } used to resolve ansible_ids to array indexes
    cached_content_types = {}  # Entries like { <content id integer>: <content_model> } used to resolve a content id to a model type
    for content_type in DABContentType.objects.all().values('id', 'model'):
        content_type_id = content_type['id']
        model = content_type['model']
        cached_content_types[content_type_id] = model
        cached_objects_index[model] = {}

    required_data = {}  # Entries like { <content_model>: { <ansible_id>|<id>: <required_data> } } Note: required_data could have references to ansible_ids

    # Populate the required_data for orgs
    org_content_type_model = DABContentType.objects.get_for_model(org_cls).model
    required_data[org_content_type_model] = {}
    for org in org_cls.objects.all().values('id', 'name', 'resource__ansible_id'):
        org_id = org['id']
        name = org['name']
        ansible_id = str(org['resource__ansible_id'])
        required_data[org_content_type_model][org_id] = {'ansible_id': ansible_id, 'name': name}
        required_data[org_content_type_model][ansible_id] = required_data[org_content_type_model][org_id]
    claims['objects'][org_content_type_model] = []

    # Populate the required_Data for teams
    team_content_type_model = DABContentType.objects.get_for_model(team_cls).model
    required_data[team_content_type_model] = {}
    for team in team_cls.objects.all().values('id', 'name', 'resource__ansible_id', 'organization__resource__ansible_id'):
        team_id = team['id']
        team_name = team['name']
        ansible_id = str(team['resource__ansible_id'])
        related_org_ansible_id = str(team['organization__resource__ansible_id'])
        required_data[team_content_type_model][team_id] = {'ansible_id': ansible_id, 'name': team_name, 'org': related_org_ansible_id}
        required_data[team_content_type_model][ansible_id] = required_data[team_content_type_model][team_id]
    claims['objects'][team_content_type_model] = []

    # We will now scan Org and Team roles and get users memberships to them.
    user_object_roles = get_user_object_roles(user)
    for role_name, ansible_id, content_type_id in user_object_roles:
        # Get the model for this content_type
        content_model_type = cached_content_types[content_type_id]

        # If the ansible_id is not in the cached_objects_index
        if ansible_id not in cached_objects_index[content_model_type]:
            # Cache the index the current len will be the next index when we append)
            cached_objects_index[content_model_type][ansible_id] = len(claims['objects'][content_model_type])
            # Add the object to the payloads objects
            claims['objects'][content_model_type].append(required_data[content_model_type][ansible_id])

        # Get the index value we want from the cache
        object_index = cached_objects_index[content_model_type][ansible_id]

        # If the role is not in the payload, insert it
        if role_name not in claims['object_roles']:
            claims['object_roles'][role_name] = {'content_type': content_model_type, 'objects': []}

        # The object is the object cache
        claims['object_roles'][role_name]['objects'].append(object_index)

    # Now we are going to trim up any team references to organizations with the index instead of the ansible ID
    # i.e. we currently have entries like: payload['objects']['team'][0]['org'] = <ansible_id>
    # and we are going to convert that to: payload['objects']['team'][0]['org'] = 0

    for team in claims['objects'][team_content_type_model]:
        org_ansible_id = team['org']
        if org_ansible_id in cached_objects_index[org_content_type_model]:
            team['org'] = cached_objects_index[org_content_type_model][org_ansible_id]
        else:
            # The user is in a team related to an org but we didn't pull that org in yet
            # Cache the index of the org, which is the current len
            cached_objects_index[org_content_type_model][org_ansible_id] = len(claims['objects'][org_content_type_model])
            org_data = required_data[org_content_type_model][org_ansible_id]
            team['org'] = len(claims['objects'][org_content_type_model])
            claims['objects'][org_content_type_model].append(org_data)

    # See if the user has any global roles
    for rd in RoleDefinition.objects.filter(content_type=None, user_assignments__user=user.pk, name__in=settings.ANSIBLE_BASE_JWT_MANAGED_ROLES):
        claims['global_roles'].append(rd.name)

    return claims
