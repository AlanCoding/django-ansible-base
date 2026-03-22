import time
from os import environ

from crum import impersonate
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from ansible_base.authentication.models import Authenticator, AuthenticatorUser
from ansible_base.oauth2_provider.models import OAuth2Application
from ansible_base.rbac import permission_registry
from ansible_base.rbac.models import DABContentType, DABPermission, RoleDefinition
from test_app.models import EncryptionModel, InstanceGroup, Inventory, Organization, Team, User


class Command(BaseCommand):
    help = 'Creates demo data for development.'

    def create_large(self, data_counts):
        "Data is not made with bulk_create at the moment to work to the resource of dab_resource_registry"
        start = time.time()
        self.stdout.write('')
        self.stdout.write('About to create large demo data set. This will take a while.')

        # Create standard models first
        created_org_ids = []
        for cls in (Organization, Team, User):
            count = data_counts[cls._meta.model_name]
            for i in range(count):
                name = f'large_{cls._meta.model_name}_{i}'
                data = {'name': name}
                if cls is User:
                    data = {'username': name}
                elif cls is Team:
                    # Use actual created organization IDs, cycling through them
                    if created_org_ids:
                        data['organization_id'] = created_org_ids[i % len(created_org_ids)]
                    else:
                        raise ValueError("Teams cannot be created before organizations")
                obj = cls.objects.create(**data)
                # Collect organization IDs for team creation
                if cls is Organization:
                    created_org_ids.append(obj.id)
            self.stdout.write(f'Created {count} {cls._meta.model_name}')

        # Create RoleDefinitions with permissions
        if 'roledefinition' in data_counts:
            rd_count = data_counts['roledefinition']
            org_ct = DABContentType.objects.get_for_model(Organization)

            for i in range(rd_count):
                # Create some sample permissions for each role definition
                perm1 = DABPermission.objects.create(name=f'Can view large role {i}', codename=f'view_large_role_{i}', content_type=org_ct)
                perm2 = DABPermission.objects.create(name=f'Can edit large role {i}', codename=f'edit_large_role_{i}', content_type=org_ct)

                # Create role definition with Organization content type
                rd = RoleDefinition.objects.create(name=f'Large Role Definition {i}', description=f'Large demo role definition {i}', content_type=org_ct)

                # Add permissions to the role definition
                rd.permissions.add(perm1, perm2)

            self.stdout.write(f'Created {rd_count} role definitions with permissions')

        # Create permission assignments for users and teams
        if created_org_ids and 'user' in data_counts and 'team' in data_counts:
            # Get created users and teams
            large_users = list(User.objects.filter(username__startswith='large_user_'))
            large_teams = list(Team.objects.filter(name__startswith='large_team_'))
            large_orgs = list(Organization.objects.filter(name__startswith='large_organization_'))
            large_rds = list(RoleDefinition.objects.filter(name__startswith='Large Role Definition'))

            # Give over 25 permissions to users
            user_permissions_given = 0
            for user in large_users:
                for rd in large_rds:
                    for org in large_orgs:
                        rd.give_permission(user, org)
                        user_permissions_given += 1
                        if user_permissions_given >= 25:
                            break
                    if user_permissions_given >= 25:
                        break
                if user_permissions_given >= 25:
                    break

            # Give over 25 permissions to teams
            team_permissions_given = 0
            for team in large_teams:
                for rd in large_rds:
                    for org in large_orgs:
                        rd.give_permission(team, org)
                        team_permissions_given += 1
                        if team_permissions_given >= 25:
                            break
                    if team_permissions_given >= 25:
                        break
                if team_permissions_given >= 25:
                    break

            self.stdout.write(f'Assigned {user_permissions_given} permissions to users')
            self.stdout.write(f'Assigned {team_permissions_given} permissions to teams')

        self.stdout.write(f'Finished creating large demo data in {time.time() - start:.2f} seconds')

    def handle(self, *args, **kwargs):
        try:
            admin = User.objects.get(username='admin')
        except User.DoesNotExist:
            raise CommandError('Must create admin user before create_demo_data')
        (awx, _) = Organization.objects.get_or_create(name='AWX_community')
        (galaxy, _) = Organization.objects.get_or_create(name='Galaxy_community')

        (spud, _) = User.objects.get_or_create(username='angry_spud')
        (team_member, _) = User.objects.get_or_create(username='team_member')
        (bull_bot, _) = User.objects.get_or_create(username='ansibullbot')
        (admin, _) = User.objects.get_or_create(username='admin')
        spud.set_password('password')
        spud.save()
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
            galaxy_inv = Inventory.objects.create(name='Galaxy Host', organization=galaxy)
            awx_inv = Inventory.objects.create(name='AWX deployment', organization=awx)
            # Objects that have no associated organization
            InstanceGroup.objects.create(name='Default')
            isolated_group = InstanceGroup.objects.create(name='Isolated Network')

        with impersonate(bull_bot):
            Team.objects.get_or_create(name='community.general maintainers', defaults={'organization': galaxy})

        ig_admin, _ = RoleDefinition.objects.get_or_create(
            name='AWX InstanceGroup admin',
            permissions=['change_instancegroup', 'delete_instancegroup', 'view_instancegroup'],
            defaults={'content_type': DABContentType.objects.get_for_model(InstanceGroup)},
        )

        org_admin_user, _ = User.objects.get_or_create(username='org_admin')
        ig_admin_user, _ = User.objects.get_or_create(username='instance_group_admin')
        RoleDefinition.objects.managed.org_admin.give_permission(org_admin_user, awx)
        ig_admin.give_permission(ig_admin_user, isolated_group)
        for user in (org_admin_user, ig_admin_user, spud):
            user.set_password('password')
            user.save()

        # Give some users team member and give that team some inventory object permissions
        for user in (spud, team_member):
            RoleDefinition.objects.managed.team_member.give_permission(spud, awx_devs)

        with impersonate(bull_bot):
            inv_admin, _ = RoleDefinition.objects.get_or_create(
                name='Inventory Admin',
                permissions=['change_inventory', 'view_inventory'],
                defaults={'content_type': permission_registry.content_type_model.objects.get_for_model(Inventory)},
            )
        for inv in (awx_inv, galaxy_inv):
            inv_admin.give_permission(awx_devs, inv)

        OAuth2Application.objects.get_or_create(
            name="Demo OAuth2 Application",
            description="Demo OAuth2 Application",
            redirect_uris="https://example.com/callback",
            authorization_grant_type="authorization-code",
            client_type="confidential",
        )

        # --- Additional RBAC scenarios for OPA migration testing ---
        self._create_opa_migration_data(admin, awx, galaxy, operator_stuff, spud, awx_devs, awx_inv, galaxy_inv, isolated_group)

        self.stdout.write('Finished creating demo data!')

        if environ.get('LARGE') and not Organization.objects.filter(name__startswith='large').exists():
            self.create_large(settings.DEMO_DATA_COUNTS)

    def _create_opa_migration_data(self, admin, awx, galaxy, operator_stuff, spud, awx_devs, awx_inv, galaxy_inv, isolated_group):
        """Create comprehensive RBAC data to exercise the OPA migration command."""
        from crum import impersonate

        from ansible_base.rbac import permission_registry
        from ansible_base.rbac.models import DABContentType, RoleDefinition

        # Extra users for cross-org and multi-role scenarios
        multi_org_user, _ = User.objects.get_or_create(username='multi_org_user')
        multi_org_user.set_password('password')
        multi_org_user.save()

        auditor_user, _ = User.objects.get_or_create(username='auditor_user')
        auditor_user.set_password('password')
        auditor_user.save()

        custom_role_user, _ = User.objects.get_or_create(username='custom_role_user')
        custom_role_user.set_password('password')
        custom_role_user.save()

        # 1. Cross-organization assignments: same user is org admin in two orgs
        RoleDefinition.objects.managed.org_admin.give_permission(multi_org_user, awx)
        RoleDefinition.objects.managed.org_admin.give_permission(multi_org_user, galaxy)
        self.stdout.write('  Created cross-org admin assignments')

        # 2. Organization member assignments
        RoleDefinition.objects.managed.org_member.give_permission(custom_role_user, awx)
        RoleDefinition.objects.managed.org_member.give_permission(spud, galaxy)
        self.stdout.write('  Created org member assignments')

        # 3. System Auditor (global/system-wide role)
        sys_auditor_rd = RoleDefinition.objects.managed.sys_auditor
        sys_auditor_rd.give_global_permission(auditor_user)
        self.stdout.write('  Created System Auditor assignment')

        # 4. Custom role definitions with various permission combos
        inv_ct = DABContentType.objects.get_for_model(Inventory)

        inv_viewer, _ = RoleDefinition.objects.get_or_create(
            name='Custom Inventory Viewer',
            permissions=['view_inventory'],
            defaults={'content_type': inv_ct, 'description': 'Custom read-only inventory role'},
        )
        inv_viewer.give_permission(custom_role_user, awx_inv)

        inv_editor, _ = RoleDefinition.objects.get_or_create(
            name='Custom Inventory Editor',
            permissions=['view_inventory', 'change_inventory'],
            defaults={'content_type': inv_ct, 'description': 'Custom edit inventory role'},
        )
        inv_editor.give_permission(custom_role_user, galaxy_inv)
        self.stdout.write('  Created custom role definitions and assignments')

        # 5. Team with role assignments (team gets permissions, members inherit)
        ops_team, _ = Team.objects.get_or_create(name='ops_team', defaults={'organization': awx})
        RoleDefinition.objects.managed.team_member.give_permission(multi_org_user, ops_team)
        RoleDefinition.objects.managed.team_member.give_permission(custom_role_user, ops_team)

        ig_ct = DABContentType.objects.get_for_model(InstanceGroup)
        ig_viewer, _ = RoleDefinition.objects.get_or_create(
            name='InstanceGroup Viewer',
            permissions=['view_instancegroup'],
            defaults={'content_type': ig_ct, 'description': 'View instance groups'},
        )
        ig_viewer.give_permission(ops_team, isolated_group)
        self.stdout.write('  Created team role assignments')

        # 6. Creator role scenario: objects created by specific users
        with impersonate(custom_role_user):
            Inventory.objects.get_or_create(
                name='CustomUser Inventory',
                defaults={'organization': awx, 'created_by': custom_role_user},
            )
        self.stdout.write('  Created creator-role test data')

        # 7. Overlapping permissions: user has both direct and team-inherited
        #    permissions on the same object (awx_inv via direct + awx_devs team)
        inv_viewer.give_permission(spud, awx_inv)
        self.stdout.write('  Created overlapping permission scenario')

        self.stdout.write('OPA migration test data created.')
