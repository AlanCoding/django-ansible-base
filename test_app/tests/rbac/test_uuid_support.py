import pytest

from ansible_base.rbac.models import RoleDefinition, RoleEvaluation, RoleEvaluationUUID, get_evaluation_model
from ansible_base.rbac.permission_registry import permission_registry
from test_app.models import Organization, UUIDModel


@pytest.mark.django_db
def test_get_evaluation_model(organization):
    assert get_evaluation_model(UUIDModel) == RoleEvaluationUUID
    assert get_evaluation_model(Organization) == RoleEvaluation
    uuid_obj = UUIDModel.objects.create(organization=organization)
    assert get_evaluation_model(uuid_obj) == RoleEvaluationUUID
    assert get_evaluation_model(organization) == RoleEvaluation


@pytest.mark.django_db
def test_filter_uuid_model(rando, organization):
    rd, _ = RoleDefinition.objects.get_or_create(
        permissions=['view_uuidmodel'], name='see UUID model', content_type=permission_registry.content_type_model.objects.get_for_model(UUIDModel)
    )
    uuid_objs = [UUIDModel.objects.create(organization=organization) for i in range(5)]
    rd.give_permission(rando, uuid_objs[1])
    rd.give_permission(rando, uuid_objs[3])

    assert rando.has_obj_perm(uuid_objs[1], 'view')
    assert set(UUIDModel.access_qs(rando)) == {uuid_objs[1], uuid_objs[3]}


@pytest.mark.django_db
def test_organization_uuid_model_permission(rando):
    rd, _ = RoleDefinition.objects.get_or_create(
        permissions=['view_uuidmodel', 'view_organization'],
        name='org-see UUID model',
        content_type=permission_registry.content_type_model.objects.get_for_model(Organization),
    )
    uuid_objs = []
    orgs = []
    for i in range(3):
        orgs.append(Organization.objects.create(name=f'org-{i}'))
        uuid_objs.append(UUIDModel.objects.create(organization=orgs[i]))
    rd.give_permission(rando, orgs[1])

    assert rando.has_obj_perm(uuid_objs[1], 'view')
    assert list(UUIDModel.access_qs(rando)) == [uuid_objs[1]]


@pytest.mark.django_db
def test_add_uuid_permission_to_role(rando, organization):
    rd, _ = RoleDefinition.objects.get_or_create(
        permissions=['view_organization'], name='will change', content_type=permission_registry.content_type_model.objects.get_for_model(Organization)
    )
    uuid_obj = UUIDModel.objects.create(organization=organization)
    rd.give_permission(rando, organization)
    assert not rando.has_obj_perm(uuid_obj, 'view')

    perm = permission_registry.permission_model.objects.get(codename='view_uuidmodel')
    rd.permissions.add(perm)
    assert rando.has_obj_perm(uuid_obj, 'view')
