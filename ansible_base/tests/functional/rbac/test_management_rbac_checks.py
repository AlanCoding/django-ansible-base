from io import StringIO

import pytest
from django.contrib.contenttypes.models import ContentType

from ansible_base.management.commands.RBAC_checks import Command
from ansible_base.models.rbac import ObjectRole, RoleDefinition
from ansible_base.tests.functional.models import Inventory


def run_and_get_output():
    cmd = Command()
    cmd.stdout = StringIO()
    cmd.handle()
    return cmd.stdout.getvalue()


@pytest.mark.django_db
def test_successful_no_data():
    assert "checking for up-to-date role evaluations" in run_and_get_output()


@pytest.mark.django_db
def test_role_definition_wrong_model(organization):
    inventory = Inventory.objects.create(name='foo-inv', organization=organization)
    rd, _ = RoleDefinition.objects.get_or_create(name='foo-def', permissions=['view_organization'])
    orole = ObjectRole.objects.create(object_id=inventory.id, content_type=ContentType.objects.get_for_model(inventory), role_definition=rd)
    assert f"Object role {orole} has permission view_organization for an unlike content type" in run_and_get_output()
