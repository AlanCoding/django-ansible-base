import pytest
from django.contrib.contenttypes.models import ContentType
from django.db.utils import IntegrityError

from ansible_base.models.rbac import ObjectRole, RoleDefinition, RoleEvaluation
from ansible_base.tests.functional.models import Organization


@pytest.mark.django_db
def test_role_definition_name_unique():
    RoleDefinition.objects.create(name='foo')
    with pytest.raises(IntegrityError):
        RoleDefinition.objects.create(name='foo')


@pytest.mark.django_db
def test_object_role_unique_rule():
    org = Organization.objects.create(name='foo')
    rd = RoleDefinition.objects.create(name='foo')
    ObjectRole.objects.create(object_id=org.id, content_type=ContentType.objects.get_for_model(org), role_definition=rd)
    with pytest.raises(IntegrityError):
        ObjectRole.objects.create(object_id=org.id, content_type=ContentType.objects.get_for_model(org), role_definition=rd)


@pytest.mark.django_db
def test_role_evaluation_unique_rule():
    org = Organization.objects.create(name='foo')
    rd = RoleDefinition.objects.create(name='foo')
    ct = ContentType.objects.get_for_model(org)
    obj_role = ObjectRole.objects.create(role_definition=rd, object_id=org.id, content_type=ct)
    RoleEvaluation.objects.create(codename='view_organization', role=obj_role, object_id=org.id, content_type_id=ct.id)
    with pytest.raises(IntegrityError):
        RoleEvaluation.objects.create(codename='view_organization', role=obj_role, object_id=org.id, content_type_id=ct.id)
