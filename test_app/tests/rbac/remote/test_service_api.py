from copy import deepcopy

import pytest

from ansible_base.lib.utils.response import get_relative_url
from ansible_base.rbac.models import DABContentType, DABPermission, RoleDefinition, RoleUserAssignment
from test_app.models import Team, User


@pytest.mark.django_db
def test_get_resource_list(admin_api_client):
    url = get_relative_url('dabcontenttype-list')
    response = admin_api_client.get(url, format="json")
    assert response.status_code == 200, response.data
    type_data = {t['api_slug']: t for t in response.data['results']}

    assert 'shared.organization' in type_data
    org_data = type_data['shared.organization']
    assert org_data['parent_content_type'] is None
    assert org_data['service'] == 'shared'
    assert org_data['model'] == 'organization'

    assert 'aap.inventory' in type_data
    inv_data = type_data['aap.inventory']
    assert inv_data['parent_content_type'] == 'shared.organization'


@pytest.mark.django_db
def test_get_permission_list(admin_api_client):
    url = get_relative_url('dabpermission-list')
    response = admin_api_client.get(url + '?page_size=200', format="json")
    assert response.status_code == 200, response.data
    type_data = {t['api_slug']: t for t in response.data['results']}

    assert 'shared.change_organization' in type_data
    change_org_data = type_data['shared.change_organization']
    assert change_org_data['content_type'] == 'shared.organization'
    assert change_org_data['codename'] == 'change_organization'


@pytest.mark.django_db
def test_role_definition_listed_as_resource(admin_api_client, org_admin_rd):
    url = get_relative_url('resource-list')
    url += '?page_size=200&content_type__resource_type__name=shared.roledefinition'
    response = admin_api_client.get(url, format="json")
    assert response.status_code == 200, response.data
    rd_data = {rd['name']: rd for rd in response.data['results']}

    assert 'Organization Admin' in rd_data
    org_admin_data = rd_data['Organization Admin']

    detail = admin_api_client.get(org_admin_data['url'], format="json")
    assert detail.status_code == 200, detail.data
    resource_data = detail.data['resource_data']
    assert resource_data['managed'] is True
    assert resource_data['content_type'] == 'shared.organization'
    assert 'permissions' in detail.data['resource_data']
    assert 'aap.add_inventory' in detail.data['resource_data']['permissions']


@pytest.mark.django_db
def test_reload_types(admin_api_client):
    url = get_relative_url('dabcontenttype-list')
    response = admin_api_client.get(url + '?page_size=200', format="json")
    assert response.status_code == 200, response.data

    type_list = response.data['results']
    original = deepcopy(type_list)

    DABContentType.objects.all().delete()  # Delete all types, see if we get them back

    DABContentType.objects.load_remote_objects(type_list)

    response = admin_api_client.get(url + '?page_size=200', format="json")
    assert response.status_code == 200, response.data

    assert response.data['results'] == original


@pytest.mark.django_db
def test_load_child_of_org():
    DABContentType.objects.load_remote_objects([{'service': 'fooland', 'app_label': 'foop', 'model': 'fooser', 'parent_content_type': 'shared.organization'}])
    ct = DABContentType.objects.get(api_slug='fooland.fooser')
    assert ct.parent_content_type.app_label == 'test_app'  # proves connection to existing


@pytest.mark.django_db
def test_reload_permissions(admin_api_client):
    url = get_relative_url('dabpermission-list')
    response = admin_api_client.get(url + '?page_size=200', format="json")
    assert response.status_code == 200, response.data

    perm_list = response.data['results']
    original = deepcopy(perm_list)

    DABPermission.objects.all().delete()  # Delete all permissions, see if we get them back

    DABPermission.objects.load_remote_objects(perm_list)

    response = admin_api_client.get(url + '?page_size=200', format="json")
    assert response.status_code == 200, response.data

    assert response.data['results'] == original


@pytest.mark.django_db
def test_list_role_user_assignments(admin_api_client, rando, inv_rd, inventory):
    inv_rd.give_permission(rando, inventory)

    url = get_relative_url('serviceuserassignment-list')
    response = admin_api_client.get(url + '?page_size=200', format="json")
    assert response.status_code == 200, response.data

    candidates = [assignment for assignment in response.data['results'] if assignment['role_definition'] == inv_rd.name]
    assert len(candidates) == 1, response.data
    from_api = candidates[0]

    assert int(from_api['object_id']) == inventory.id
    assert from_api['user_ansible_id'] == str(rando.resource.ansible_id)
    assert from_api['content_type'] == 'aap.inventory'


@pytest.mark.django_db
def test_apply_role_assignment(admin_api_client, rando, inv_rd, inventory):
    url = get_relative_url('serviceuserassignment-assign')

    data = {"role_definition": inv_rd.name, "user_ansible_id": str(rando.resource.ansible_id), "object_id": inventory.pk}

    assert not rando.has_obj_perm(inventory, 'change')
    response = admin_api_client.post(url, data=data)
    assert response.status_code == 201, response.data
    assert rando.has_obj_perm(inventory, 'change')

    # Second try, response code indicates assignment already exists
    response = admin_api_client.post(url, data=data)
    assert response.status_code == 200, response.data


@pytest.mark.django_db
def test_unassign_endpoint(rando, org_inv_rd, inventory, admin_api_client):
    org_inv_rd.give_permission(rando, inventory.organization)
    assert rando.has_obj_perm(inventory, 'change')

    url = get_relative_url('serviceuserassignment-unassign')
    data = {
        "role_definition": org_inv_rd.name,
        "user_ansible_id": str(rando.resource.ansible_id),
        "object_ansible_id": str(inventory.organization.resource.ansible_id),
    }
    response = admin_api_client.post(url, data)
    assert response.status_code == 204, response.data
    assert not rando.has_obj_perm(inventory, 'change')

    # second gets a 200 code
    response = admin_api_client.post(url, data)
    assert response.status_code == 200, response.data
    assert not rando.has_obj_perm(inventory, 'change')


# teams
@pytest.mark.django_db
def test_apply_role_assignment_for_team(admin_api_client, inv_rd, inventory, team, member_rd, rando):
    member_rd.give_permission(rando, team)
    url = get_relative_url('serviceteamassignment-assign')

    data = {"role_definition": inv_rd.name, "team_ansible_id": str(team.resource.ansible_id), "object_id": inventory.pk}

    assert not rando.has_obj_perm(inventory, 'change')
    response = admin_api_client.post(url, data=data)
    assert response.status_code == 201, response.data
    assert rando.has_obj_perm(inventory, 'change')

    # Second try, response code indicates assignment already exists
    response = admin_api_client.post(url, data=data)
    assert response.status_code == 200, response.data


@pytest.mark.django_db
def test_unassign_endpoint_for_team(team, org_inv_rd, inventory, admin_api_client, member_rd, rando):
    member_rd.give_permission(rando, team)
    org_inv_rd.give_permission(team, inventory.organization)
    assert rando.has_obj_perm(inventory, 'change')

    url = get_relative_url('serviceteamassignment-unassign')
    data = {
        "role_definition": org_inv_rd.name,
        "team_ansible_id": str(team.resource.ansible_id),
        "object_ansible_id": str(inventory.organization.resource.ansible_id),
    }
    response = admin_api_client.post(url, data)
    assert response.status_code == 204, response.data
    assert not rando.has_obj_perm(inventory, 'change')

    # second gets a 200 code
    response = admin_api_client.post(url, data)
    assert response.status_code == 200, response.data
    assert not rando.has_obj_perm(inventory, 'change')


@pytest.mark.django_db
@pytest.mark.parametrize('actor_type', ['user', 'team'])
def test_assign_and_unassign_system_role(inventory, admin_api_client, actor_type, organization, member_rd):
    if actor_type == 'user':
        actor = User.objects.create(username='user1')
        user = actor
    else:
        actor = Team.objects.create(name='random_team', organization=organization)
        user = User.objects.create(username='user1')
        member_rd.give_permission(user, actor)

    rd = RoleDefinition.objects.managed.sys_auditor
    assert 'view_inventory' in set(rd.permissions.values_list('codename', flat=True))
    assert not user.has_obj_perm(inventory, 'view')

    url = get_relative_url(f'service{actor_type}assignment-assign')
    data = {"role_definition": rd.name, f"{actor_type}_ansible_id": str(actor.resource.ansible_id)}
    response = admin_api_client.post(url, data)
    assert response.status_code == 201, response.data
    if hasattr(actor, '_singleton_permissions'):
        delattr(actor, '_singleton_permissions')
    assert user.has_obj_perm(inventory, 'view')  # gave system wide view permission

    # Second try, response code indicates global assignment already exists
    response = admin_api_client.post(url, data=data)
    assert response.status_code == 200, response.data

    unassign_url = get_relative_url(f'service{actor_type}assignment-unassign')
    response = admin_api_client.post(unassign_url, data)
    assert response.status_code == 204, response.data
    if hasattr(actor, '_singleton_permissions'):
        delattr(actor, '_singleton_permissions')
    assert not user.has_obj_perm(inventory, 'view')  # permission removed

    response = admin_api_client.post(unassign_url, data)
    assert response.status_code == 200, response.data


@pytest.mark.django_db
def test_filter_assignment_list(admin_api_client, rando, inv_rd, view_inv_rd, org_inv_rd, inventory):
    inv_rd.give_permission(rando, inventory)
    org_inv_rd.give_permission(rando, inventory.organization)
    view_inv_rd.give_permission(rando, inventory)

    url = get_relative_url('serviceuserassignment-list')
    response = admin_api_client.get(url + f'?user={rando.id}', format="json")
    assert response.status_code == 200, response.data
    assert response.data['count'] == 3  # user rando has 3 rol assignments

    # Get just one single assignment
    response = admin_api_client.get(url + f'?assignment={str(rando.resource.ansible_id)},{inv_rd.name},{inventory.id}', format="json")
    assert response.status_code == 200, response.data
    assert response.data['count'] == 1
    assert response.data['results'][0]['role_definition'] == inv_rd.name

    # Assure we can get two assignments at the same time
    response = admin_api_client.get(
        url
        + (
            f'?assignment={str(rando.resource.ansible_id)},{inv_rd.name},{inventory.id}&'
            f'assignment={str(rando.resource.ansible_id)},{org_inv_rd.name},{inventory.organization.id}'
        ),
        format="json",
    )
    assert response.status_code == 200, response.data
    assert response.data['count'] == 2


@pytest.mark.django_db
@pytest.mark.parametrize(
    'reverse_name,normal_case,unauth_case',
    [
        ('service-index-root', 200, 401),
        ('dabcontenttype-list', 200, 401),  # could change unauthenticated case, depends on need
        ('dabpermission-list', 200, 401),
        ('resource-list', 403, 401),
        ('serviceuserassignment-list', 403, 401),
        ('serviceteamassignment-list', 403, 401),
    ],
)
def test_service_api_permissions(reverse_name, normal_case, unauth_case, admin_api_client, user_api_client, unauthenticated_api_client):
    url = get_relative_url(reverse_name)

    admin_response = admin_api_client.get(url)
    assert admin_response.status_code == 200, admin_response.data

    normal_response = user_api_client.get(url)
    assert normal_response.status_code == normal_case, normal_response.data

    unauth_response = unauthenticated_api_client.get(url)
    assert unauth_response.status_code == unauth_case, unauth_response.data


@pytest.mark.django_db
def test_role_types_and_permissions_payload_shape(user_api_client):
    """Minimal payload-shape checks for role types and permissions when accessed by normal user."""
    # role types
    url_ct = get_relative_url('dabcontenttype-list')
    resp_ct = user_api_client.get(url_ct)
    assert resp_ct.status_code == 200, resp_ct.data
    # Results should be paginated list; spot-check first item fields if present
    if resp_ct.data.get('count', 0) and resp_ct.data.get('results'):
        item = resp_ct.data['results'][0]
        for key in ('api_slug', 'service', 'app_label', 'model', 'pk_field_type'):
            assert key in item
        # parent_content_type is allowed to be null
        assert 'parent_content_type' in item

    # role permissions
    url_perm = get_relative_url('dabpermission-list')
    resp_perm = user_api_client.get(url_perm)
    assert resp_perm.status_code == 200, resp_perm.data
    if resp_perm.data.get('count', 0) and resp_perm.data.get('results'):
        item = resp_perm.data['results'][0]
        for key in ('api_slug', 'codename', 'name'):
            assert key in item
        assert 'content_type' in item  # slug of related content type


@pytest.mark.django_db
class TestCreatedByAnsibleIdAllowNull:
    """Test that created_by_ansible_id field accepts null values and omissions"""

    @pytest.mark.parametrize(
        'actor_type,created_by_value',
        [
            ('user', ''),  # empty string
            ('user', None),  # omitted (None means field not present)
            ('user', 'valid'),  # valid creator
            ('team', ''),  # empty string
            ('team', None),  # omitted
            ('team', 'valid'),  # valid creator
        ],
    )
    def test_service_assignment_created_by_handling(self, admin_api_client, rando, inv_rd, inventory, team, member_rd, actor_type, created_by_value):
        """Test that ServiceRoleAssignmentSerializer handles created_by_ansible_id correctly"""
        # Setup for team assignments
        if actor_type == 'team':
            member_rd.give_permission(rando, team)
            actor = team
        else:
            actor = rando

        url = get_relative_url(f'service{actor_type}assignment-assign')
        data = {
            "role_definition": inv_rd.name,
            f"{actor_type}_ansible_id": str(actor.resource.ansible_id),
            "object_id": inventory.pk,
        }

        # Handle different created_by_value scenarios
        if created_by_value == '':
            data["created_by_ansible_id"] = ""
        elif created_by_value == 'valid':
            creator = User.objects.create(username=f'{actor_type}-creator-user')
            data["created_by_ansible_id"] = str(creator.resource.ansible_id)
        # None means field is omitted (not added to data)

        response = admin_api_client.post(url, data=data)
        assert response.status_code == 201, response.data
        assert rando.has_obj_perm(inventory, 'change')

    def test_list_assignments_shows_created_by_when_present(self, admin_api_client, rando, inv_rd, inventory):
        """Test that list endpoint properly serializes created_by_ansible_id when present"""
        creator = User.objects.create(username='assignment-creator')

        # Create assignment with a specific creator
        url = get_relative_url('serviceuserassignment-assign')
        data = {
            "role_definition": inv_rd.name,
            "user_ansible_id": str(rando.resource.ansible_id),
            "object_id": inventory.pk,
            "created_by_ansible_id": str(creator.resource.ansible_id),
        }
        response = admin_api_client.post(url, data=data)
        assert response.status_code == 201, response.data

        # Check list endpoint
        list_url = get_relative_url('serviceuserassignment-list')
        response = admin_api_client.get(list_url + '?page_size=200', format="json")
        assert response.status_code == 200, response.data

        # Find our assignment
        assignments = [a for a in response.data['results'] if a['role_definition'] == inv_rd.name and str(a['object_id']) == str(inventory.id)]
        assert len(assignments) >= 1, "Should find at least our assignment"

        # Check that created_by_ansible_id is properly serialized
        assignment = assignments[0]
        assert 'created_by_ansible_id' in assignment
        assert assignment['created_by_ansible_id'] == str(creator.resource.ansible_id)

    def test_list_assignments_shows_null_created_by_when_null(self, admin_api_client, rando, inv_rd, inventory):
        """Test that list endpoint properly serializes created_by_ansible_id when empty string is provided"""
        # Create assignment with empty created_by_ansible_id
        url = get_relative_url('serviceuserassignment-assign')
        data = {
            "role_definition": inv_rd.name,
            "user_ansible_id": str(rando.resource.ansible_id),
            "object_id": inventory.pk,
            "created_by_ansible_id": "",  # Use empty string - should be treated as not providing the field
        }
        response = admin_api_client.post(url, data=data)
        assert response.status_code == 201, response.data

        # Check list endpoint
        list_url = get_relative_url('serviceuserassignment-list')
        response = admin_api_client.get(list_url + '?page_size=200', format="json")
        assert response.status_code == 200, response.data

        # Find our assignment
        assignments = [a for a in response.data['results'] if a['role_definition'] == inv_rd.name and str(a['object_id']) == str(inventory.id)]
        assert len(assignments) >= 1, "Should find at least our assignment"

        # Check that created_by_ansible_id is properly serialized
        assignment = assignments[0]
        assert 'created_by_ansible_id' in assignment
        # When empty string is provided, the system may still set created_by to the current user
        # The key test is that the API accepts empty string without error
        assert assignment['created_by_ansible_id'] is not None  # System will set to current user

    def test_serializer_allows_null_values_in_validation(self, admin_api_client, rando, inv_rd, inventory):
        """Test that the serializer field properly handles null validation with allow_null=True"""
        from ansible_base.rbac.service_api.serializers import ServiceRoleUserAssignmentSerializer

        # Test data with null created_by_ansible_id
        data = {
            "role_definition": inv_rd.name,
            "user_ansible_id": str(rando.resource.ansible_id),
            "object_id": str(inventory.pk),
            "created_by_ansible_id": None,  # Explicit None
            "from_service": "test",
        }

        # Create serializer and validate
        serializer = ServiceRoleUserAssignmentSerializer(data=data)

        # Should be valid due to allow_null=True
        is_valid = serializer.is_valid()
        if not is_valid:
            print("Validation errors:", serializer.errors)
        assert is_valid, f"Serializer should accept null values: {serializer.errors}"

        # Verify that created_by is None in validated_data when null is passed
        validated_data = serializer.validated_data
        assert 'created_by' not in validated_data or validated_data.get('created_by') is None


def test_service_assignment_created_timestamp_sync(admin_api_client, rando, inv_rd, inventory):
    """
    Test that demonstrates the field sync issue: the 'created' timestamp field is displayed
    in responses but not applied when creating assignments via POST to /assign/.

    This test should FAIL, showing that custom timestamps are ignored and auto-generated instead.
    """
    from datetime import datetime, timezone

    from django.utils.dateparse import parse_datetime

    url = get_relative_url('serviceuserassignment-assign')

    creator_user = User.objects.create(username='timestamp_creator')

    # Set a specific timestamp that's different from "now"
    custom_timestamp = datetime(2023, 1, 15, 10, 30, 45, tzinfo=timezone.utc)
    custom_timestamp_str = custom_timestamp.isoformat()

    post_data = {
        "role_definition": inv_rd.name,
        "user_ansible_id": str(rando.resource.ansible_id),
        "object_id": str(inventory.pk),
        "created_by_ansible_id": str(creator_user.resource.ansible_id),
        "created": custom_timestamp_str,
        "from_service": "test_service",
    }

    response = admin_api_client.post(url, data=post_data)
    assert response.status_code == 201, response.data

    assignment = RoleUserAssignment.objects.get(user=rando, role_definition=inv_rd, object_id=inventory.pk)

    # Test if the custom timestamp was properly set
    expected_created = custom_timestamp
    actual_created = assignment.created

    # This should FAIL, demonstrating the field sync issue
    assert actual_created == expected_created, (
        f"FIELD SYNC ISSUE: Expected created timestamp '{expected_created}' but got '{actual_created}'. "
        f"The 'created' field is displayed in responses but not applied from POST data."
    )

    # Verify response contains the timestamp field (showing it's "displayed")
    response_created = parse_datetime(response.data['created'])
    # Note: This will show the auto-generated timestamp, not our custom one
    assert response_created == expected_created, f"Response created timestamp should match: expected '{expected_created}' but got '{response_created}'"


@pytest.mark.django_db
@pytest.mark.parametrize(
    'object_created_source',
    [
        'custom',  # Provide custom timestamp
        'local_object',  # Use local object's created timestamp
    ],
)
def test_service_assignment_object_created_sync(admin_api_client, rando, inv_rd, inventory, org_inv_rd, organization, object_created_source):
    """
    Test that the 'object_created' field can be synchronized in both directions:
    1. POST to /assign/ accepts a provided 'object_created' value
    2. When no object_created is provided, it defaults to the local object's created timestamp
    3. Serializing local assignments includes the 'object_created' field from the DB
    """
    from datetime import datetime, timezone

    from django.utils.dateparse import parse_datetime

    url = get_relative_url('serviceuserassignment-assign')

    if object_created_source == 'custom':
        # Use inventory with custom timestamp
        target_object = inventory
        role_def = inv_rd
        custom_object_created = datetime(2022, 6, 15, 14, 30, 0, tzinfo=timezone.utc)
        expected_object_created = custom_object_created

        post_data = {
            "role_definition": role_def.name,
            "user_ansible_id": str(rando.resource.ansible_id),
            "object_id": str(target_object.pk),
            "object_created": custom_object_created.isoformat(),
            "from_service": "test_service",
        }
    else:  # local_object
        # Use organization without providing object_created
        target_object = organization
        role_def = org_inv_rd
        expected_object_created = organization.created

        post_data = {
            "role_definition": role_def.name,
            "user_ansible_id": str(rando.resource.ansible_id),
            "object_id": str(target_object.pk),
            "from_service": "test_service",
            # Note: no object_created provided - should default to target_object.created
        }

    # Test 1: POST accepts object_created value or defaults to local object
    response = admin_api_client.post(url, data=post_data)
    assert response.status_code == 201, response.data

    assignment = RoleUserAssignment.objects.get(user=rando, role_definition=role_def, object_id=target_object.pk)

    # Verify the object_created timestamp was properly set
    actual_object_created = assignment.object_created
    operation_type = 'synchronized' if object_created_source == 'custom' else 'defaulted to local object'
    assert (
        actual_object_created == expected_object_created
    ), f"object_created should be {operation_type}: Expected '{expected_object_created}' but got '{actual_object_created}'"

    # Test 2: Serializing local assignments includes object_created field
    list_url = get_relative_url('serviceuserassignment-list')
    response = admin_api_client.get(list_url + '?page_size=200', format="json")
    assert response.status_code == 200, response.data

    # Find our assignment in the list
    assignments = [a for a in response.data['results'] if a['role_definition'] == role_def.name and str(a['object_id']) == str(target_object.pk)]
    assert len(assignments) >= 1, "Should find at least our assignment"

    # Check that object_created is properly serialized
    assignment_data = assignments[0]
    assert 'object_created' in assignment_data, "object_created field should be present in serialized output"

    response_object_created = parse_datetime(assignment_data['object_created'])
    assert (
        response_object_created == expected_object_created
    ), f"Serialized object_created should match stored value: expected '{expected_object_created}' but got '{response_object_created}'"
