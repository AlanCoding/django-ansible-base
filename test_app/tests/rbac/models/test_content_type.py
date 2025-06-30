import pytest
from django.db import models
from django.test import TestCase
from django.test.utils import isolate_apps

from ansible_base.rbac.models import DABContentType
from ansible_base.rbac.remote import RemoteObject
from test_app.models import Inventory


@pytest.mark.django_db
def test_post_migrate_creates_contenttype():
    ct = DABContentType.objects.get(app_label="test_app", model="inventory")
    assert ct.service == "aap"


@pytest.mark.django_db
class DABContentTypeTests(TestCase):
    """These tests originally came from Django contenttypes"""
    def setUp(self):
        DABContentType.objects.clear_cache()
        self.addCleanup(DABContentType.objects.clear_cache)

    def test_lookup_cache(self):
        with self.assertNumQueries(1):
            DABContentType.objects.get_for_model(Inventory)
        with self.assertNumQueries(0):
            ct = DABContentType.objects.get_for_model(Inventory)
        with self.assertNumQueries(0):
            DABContentType.objects.get_for_id(ct.id)
        with self.assertNumQueries(0):
            DABContentType.objects.get_by_natural_key(
                ct.service,
                ct.app_label,
                ct.model,
            )
        DABContentType.objects.clear_cache()
        with self.assertNumQueries(1):
            DABContentType.objects.get_for_model(Inventory)

    @isolate_apps("tests")
    def test_get_for_model_create_contenttype(self):
        class ModelCreatedOnTheFly(models.Model):
            name = models.CharField(max_length=10)

            class Meta:
                app_label = "tests"

        ct = DABContentType.objects.get_for_model(ModelCreatedOnTheFly)
        assert ct.app_label == "tests"
        assert ct.model == "modelcreatedonthefly"


@pytest.mark.django_db
def test_get_object_for_this_type_remote():
    """Remote objects should return a remote proxy."""
    ct = DABContentType.objects.create(
        service="remote_proj",
        app_label="testapp",
        model="book",
    )

    obj = ct.get_object_for_this_type(pk=1)

    assert isinstance(obj, RemoteObject)
    assert obj.object_id == 1
    assert obj.content_type == ct


@pytest.mark.django_db
def test_get_all_objects_for_this_type_remote():
    ct = DABContentType.objects.create(
        service="remote_proj2",
        app_label="testapp",
        model="book",
    )

    objs = ct.get_all_objects_for_this_type(pk__in=[1, 2])

    assert [o.object_id for o in objs] == [1, 2]
    assert all(isinstance(o, RemoteObject) for o in objs)
