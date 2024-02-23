from os import environ

from crum import impersonate
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand

from ansible_base.authentication.models import Authenticator, AuthenticatorUser
from ansible_base.rbac.models import RoleDefinition
from test_app.models import EncryptionModel, InstanceGroup, Inventory, Organization, Team, User


class Command(BaseCommand):
    help = 'Creates demo data for development.'

    def handle(self, *args, **kwargs):
        (awx, _) = Organization.objects.get_or_create(name='AWX_community')
        (galaxy, _) = Organization.objects.get_or_create(name='Galaxy_community')

        (spud, _) = User.objects.get_or_create(username='angry_spud')
        (bull_bot, _) = User.objects.get_or_create(username='ansibullbot')
        (admin, _) = User.objects.get_or_create(username='admin')
        admin.is_staff = True
        admin.is_superuser = True
        admin_password = environ.get('DJANGO_SUPERUSER_PASSWORD', 'admin')
        admin.set_password(admin_password)
        admin.save()

        with impersonate(spud):
            Team.objects.get_or_create(name='awx_docs', defaults={'organization': awx})
            awx_devs, _ = Team.objects.get_or_create(name='awx_devs', defaults={'organization': awx})
            EncryptionModel.objects.get_or_create(
                name='foo', defaults={'testing1': 'should not show this value!!', 'testing2': 'this value should also not be shown!'}
            )
            operator_stuff, _ = Organization.objects.get_or_create(name='Operator_community')
            (db_authenticator, _) = Authenticator.objects.get_or_create(
                name='Local Database Authenticator',
                defaults={
                    'enabled': True,
                    'create_objects': True,
                    'configuration': {},
                    'remove_users': False,
                    'type': 'ansible_base.authentication.authenticator_plugins.local',
                },
            )
            AuthenticatorUser.objects.get_or_create(
                uid=admin.username,
                defaults={
                    'user': admin,
                    'provider': db_authenticator,
                },
            )

            # Inventory objects exist inside of an organization
            Inventory.objects.create(name='K8S clusters', organization=operator_stuff)
            Inventory.objects.create(name='Galaxy Host', organization=galaxy)
            Inventory.objects.create(name='AWX deployment', organization=awx)
            # Objects that have no associated organization
            InstanceGroup.objects.create(name='Default')
            isolated_group = InstanceGroup.objects.create(name='Isolated Network')

        with impersonate(bull_bot):
            Team.objects.get_or_create(name='community.general maintainers', defaults={'organization': galaxy})

        # NOTE: managed role definitions are turned off, you could turn them on and get rid of these
        awx_perms = list(Permission.objects.filter(content_type__model__in=['organization', 'inventory']).values_list('codename', flat=True))
        org_admin, _ = RoleDefinition.objects.get_or_create(
            name='AWX Organization admin permissions', permissions=awx_perms, defaults={'content_type': ContentType.objects.get_for_model(Organization)}
        )
        ig_admin, _ = RoleDefinition.objects.get_or_create(
            name='AWX InstanceGroup admin',
            permissions=['change_instancegroup', 'delete_instancegroup', 'view_instancegroup'],
            defaults={'content_type': ContentType.objects.get_for_model(InstanceGroup)},
        )
        team_member, _ = RoleDefinition.objects.get_or_create(
            name='Special Team member role', permissions=['view_team', 'member_team'], defaults={'content_type': ContentType.objects.get_for_model(Team)}
        )

        org_admin_user, _ = User.objects.get_or_create(username='org_admin')
        ig_admin_user, _ = User.objects.get_or_create(username='instance_group_admin')
        org_admin.give_permission(org_admin_user, awx)
        ig_admin.give_permission(ig_admin_user, isolated_group)
        for user in (org_admin_user, ig_admin_user, spud):
            user.set_password('password')
            user.save()

        team_member.give_permission(spud, awx_devs)

        self.stdout.write('Finished creating demo data!')
        self.stdout.write(f'Admin user password: {admin_password}')
