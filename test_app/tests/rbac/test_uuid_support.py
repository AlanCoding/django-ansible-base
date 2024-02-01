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
