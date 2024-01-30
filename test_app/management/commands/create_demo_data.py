from crum import impersonate
from django.core.management.base import BaseCommand
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import Permission

from ansible_base.rbac.models import RoleDefinition

from test_app.models import EncryptionModel, Organization, Team, User, Inventory, InstanceGroup


class Command(BaseCommand):
    help = 'Creates demo data for development.'

    def handle(self, *args, **kwargs):
        if Organization.objects.exists():
            print('It looks like you already have data loaded, great!')
            return

        awx = Organization.objects.create(name='AWX_community')
        galaxy = Organization.objects.create(name='Galaxy_community')

        spud = User.objects.create(username='angry_spud')
        bull_bot = User.objects.create(username='ansibullbot')

        with impersonate(spud):
            Team.objects.create(name='awx_docs', organization=awx)
            awx_devs = Team.objects.create(name='awx_devs', organization=awx)
            operator_stuff = Organization.objects.create(name='Operator_community')

            EncryptionModel.objects.create(name='foo', testing1='should not show this value!!', testing2='this value should also not be shown!')
            # Inventory objects exist inside of an organization
            Inventory.objects.create(name='K8S clusters', organization=operator_stuff)
            Inventory.objects.create(name='Galaxy Host', organization=galaxy)
            Inventory.objects.create(name='AWX deployment', organization=awx)
            # Objects that have no associated organization
            InstanceGroup.objects.create(name='Default')
            isolated_group = InstanceGroup.objects.create(name='Isolated Network')

        with impersonate(bull_bot):
            Team.objects.create(name='community.general maintainers', organization=galaxy)

        # NOTE: managed role definitions are turned off, you could turn them on and get rid of these
        awx_perms = list(Permission.objects.filter(content_type__model__in=['organization', 'inventory']).values_list('codename', flat=True))
        org_admin = RoleDefinition.objects.create_from_permissions(
            name='AWX Organization admin permissions', content_type=ContentType.objects.get_for_model(Organization), permissions=awx_perms
        )
        ig_admin = RoleDefinition.objects.create_from_permissions(
            name='AWX InstanceGroup admin',
            content_type=ContentType.objects.get_for_model(InstanceGroup),
            permissions=['change_instancegroup', 'delete_instancegroup', 'view_instancegroup']
        )
        team_member = RoleDefinition.objects.create_from_permissions(
            name='Special Team member role',
            content_type=ContentType.objects.get_for_model(Team),
            permissions=['view_inventory', 'member_inventory']
        )

        org_admin_user = User.objects.create(username='org_admin')
        ig_admin_user = User.objects.create(username='instance_group_admin')
        org_admin.give_permission(org_admin_user, awx)
        ig_admin.give_permission(ig_admin_user, isolated_group)
        for user in (org_admin_user, ig_admin_user, spud):
            user.set_password('password')
            user.save()

        team_member.give_permission(spud, awx_devs)

        print('Finished creating demo data!')
