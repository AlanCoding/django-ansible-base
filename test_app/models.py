import uuid

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.contrib.contenttypes.models import ContentType
from django.db import models

from ansible_base.lib.abstract_models import AbstractOrganization, AbstractTeam
from ansible_base.lib.abstract_models.common import CommonModel, NamedCommonModel
from ansible_base.lib.utils.models import user_summary_fields
from ansible_base.rbac import permission_registry


class Organization(AbstractOrganization):
    class Meta:
        app_label = 'test_app'
        # For root resources (no parent) we exclude the add permission which is a global permission
        default_permissions = ('change', 'delete', 'view')


class User(AbstractUser, CommonModel):
    def summary_fields(self):
        return user_summary_fields(self)

    singleton_roles = models.ManyToManyField('dab_rbac.RoleDefinition', related_name='singleton_users', blank=True)


class Team(AbstractTeam):
    tracked_users = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='tracked_teams', blank=True)
    team_parents = models.ManyToManyField('Team', related_name='team_children', blank=True)

    singleton_roles = models.ManyToManyField('dab_rbac.RoleDefinition', related_name='singleton_teams', blank=True)

    encryptioner = models.ForeignKey('test_app.EncryptionModel', on_delete=models.SET_NULL, null=True)

    class Meta:
        app_label = 'test_app'
        abstract = False
        unique_together = [('organization', 'name')]
        ordering = ('organization__name', 'name')
        permissions = [('member_team', 'Has all roles assigned to this team')]


class ResourceMigrationTestModel(models.Model):
    name = models.CharField(max_length=255)


class EncryptionModel(NamedCommonModel):
    router_basename = 'encryption_test_model'

    class Meta:
        app_label = "test_app"

    encrypted_fields = ['testing1', 'testing2']

    testing1 = models.CharField(max_length=400, null=True, default='a')
    testing2 = models.CharField(max_length=400, null=True, default='b')


class RelatedFieldsTestModel(CommonModel):
    users = models.ManyToManyField(User, related_name='related_fields_test_model_users')

    teams_with_no_view = models.ManyToManyField(Team, related_name='related_fields_test_model_teams_with_no_view')

    more_teams = models.ManyToManyField(Team, related_name='related_fields_test_model_more_teams')

    ignore_relations = ['teams_with_no_view']


class Inventory(models.Model):
    "Simple example of a child object, it has a link to its parent organization"
    name = models.CharField(max_length=512)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)

    class Meta:
        app_label = 'test_app'
        permissions = [('update_inventory', 'Do inventory updates')]

    def summary_fields(self):
        return {"id": self.id, "name": self.name}


class InstanceGroup(models.Model):
    "Example of an object with no parent object, a root resource, a lone wolf"
    name = models.CharField(max_length=512)

    class Meta:
        app_label = 'test_app'
        default_permissions = ('change', 'delete', 'view')


class Namespace(models.Model):
    "Example of a child object with its own child objects"
    name = models.CharField(max_length=64, unique=True, blank=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)


class CollectionImport(models.Model):
    "Example of a child of a child object, organization is implied by its namespace"
    name = models.CharField(max_length=64, unique=True, blank=False)
    namespace = models.ForeignKey(Namespace, on_delete=models.CASCADE)


class ExampleEvent(models.Model):
    "Example of a model which is not registered in permission registry in the first place"
    name = models.CharField(max_length=64, unique=True, blank=False)


class Cow(models.Model):
    "This model has a special action it can do, which is to give advice"
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)

    class Meta:
        app_label = 'test_app'
        permissions = [('say_cow', 'Make cow say some advice')]


class UUIDModel(models.Model):
    "Tests that system works with a model that has a string uuid primary key"
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)


class PositionModel(models.Model):
    "Uses a primary key other than id to test that everything still works"
    position = models.BigIntegerField(primary_key=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)


class WeirdPerm(models.Model):
    "Uses a weird permission name"
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)

    class Meta:
        app_label = 'test_app'
        permissions = [("I'm a lovely coconut", "You can be a lovely coconut with this object"), ("crack", "Can crack open this coconut")]


class CustomPermission(models.Model):
    "Used for testing using a custom permission, only used in special cases"
    name = models.CharField("name", max_length=255)
    content_type = models.ForeignKey(ContentType, models.CASCADE, verbose_name="content type")
    codename = models.CharField("codename", max_length=100)

    class Meta:
        app_label = 'test_app'
        unique_together = [["content_type", "codename"]]


permission_registry.register(Organization, Inventory, Namespace, Team, Cow, UUIDModel, PositionModel, WeirdPerm)
permission_registry.register(CollectionImport, parent_field_name='namespace')
permission_registry.register(InstanceGroup, parent_field_name=None)

permission_registry.track_relationship(Team, 'tracked_users', 'team-member')
permission_registry.track_relationship(Team, 'team_parents', 'team-member')
