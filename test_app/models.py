from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models

from ansible_base.lib.abstract_models import AbstractOrganization, AbstractTeam
from ansible_base.lib.abstract_models.common import CommonModel, NamedCommonModel
from ansible_base.lib.utils.models import user_summary_fields
from ansible_base.rbac import permission_registry


class EncryptionModel(NamedCommonModel):
    class Meta:
        app_label = "test_app"

    encrypted_fields = ['testing1', 'testing2']

    testing1 = models.CharField(max_length=1, null=True, default='a')
    testing2 = models.CharField(max_length=1, null=True, default='b')


class Organization(AbstractOrganization):
    pass


class User(AbstractUser, CommonModel):
    def summary_fields(self):
        return user_summary_fields(self)

    singleton_roles = models.ManyToManyField('dab_rbac.RoleDefinition', related_name='singleton_users', blank=True)


class Team(AbstractTeam):
    tracked_users = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='tracked_teams', blank=True)
    team_parents = models.ManyToManyField('Team', related_name='team_children', blank=True)

    singleton_roles = models.ManyToManyField('dab_rbac.RoleDefinition', blank=True)

    class Meta:
        app_label = 'test_app'
        permissions = [('member_team', 'Has all roles assigned to this team')]


class Inventory(models.Model):
    "Simple example of a child object, it has a link to its parent organization"
    name = models.CharField(max_length=512)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)

    class Meta:
        app_label = 'test_app'
        permissions = [('update_inventory', 'Do inventory updates')]


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


permission_registry.register(Organization, Inventory, Namespace, Team)
permission_registry.register(CollectionImport, parent_field_name='namespace')
permission_registry.register(InstanceGroup, parent_field_name=None)

permission_registry.track_relationship(Team, 'tracked_users', 'team-member')
permission_registry.track_relationship(Team, 'team_parents', 'team-member')
