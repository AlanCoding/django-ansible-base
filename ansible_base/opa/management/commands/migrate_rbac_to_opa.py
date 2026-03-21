import logging
from collections import defaultdict

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from ansible_base.opa.models import GroupRoleAssignment, OPAGroup, Policy, Role
from ansible_base.opa.registry import opa_registry
from ansible_base.opa.rego.sync import sync_to_opa

logger = logging.getLogger(__name__)

# Permission codename prefixes that map to OPA actions
ACTION_PREFIX_MAP = {
    "view": "read",
    "change": "change",
    "delete": "delete",
    "add": "add",
}


class Command(BaseCommand):
    help = "Migrate RBAC role definitions and assignments to OPA roles, policies, and groups."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="Report what would be migrated without writing.")
        parser.add_argument("--sync", action="store_true", help="Run sync_opa after migration.")

    def handle(self, *args, **options):
        self.dry_run = options["dry_run"]
        if self.dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN - no changes will be written"))
            self.stdout.write("")

        self._ensure_user_groups()
        self._migrate_role_definitions()
        self._migrate_assignments()

        if options["sync"] and not self.dry_run:
            self.stdout.write("")
            self.stdout.write("Syncing to OPA...")
            sync_to_opa(debounce_seconds=0)
            self.stdout.write(self.style.SUCCESS("OPA sync complete."))

    def _build_resource_model_map(self):
        """Build mapping from Django model name to OPA resource name."""
        model_to_resource = {}
        for resource_name, resource_def in opa_registry.resources.items():
            model_path = resource_def["model"].lower()
            # model_path is like "test_app.inventory"
            model_to_resource[model_path] = resource_name
        return model_to_resource

    def _perm_to_resource_action(self, perm, model_to_resource):
        """Map a DABPermission to an (opa_resource, opa_action) or None."""
        codename = perm.codename
        ct = perm.content_type

        # codename is like "change_inventory", "view_organization"
        parts = codename.split("_", 1)
        if len(parts) != 2:
            return None

        django_action, model_name = parts
        opa_action = ACTION_PREFIX_MAP.get(django_action)
        if opa_action is None:
            return None

        # Find OPA resource by content type
        model_path = f"{ct.app_label}.{ct.model}".lower()
        resource_name = model_to_resource.get(model_path)
        if resource_name is None:
            return None

        # Verify the action is registered for this resource
        try:
            valid_actions = opa_registry.get_actions(resource_name)
        except ValueError:
            return None
        if opa_action not in valid_actions:
            return None

        return resource_name, opa_action

    def _ensure_user_groups(self):
        """Ensure per-user OPAGroups exist for all users."""
        User = get_user_model()
        users = User.objects.all()
        created = 0
        for user in users:
            group_name = f"user:{user.pk}"
            if not OPAGroup.objects.filter(name=group_name).exists():
                if not self.dry_run:
                    group = OPAGroup.objects.create(name=group_name, managed=True)
                    group.users.add(user)
                created += 1
        if created:
            self.stdout.write(f"  Created {created} per-user OPAGroups")

    def _migrate_role_definitions(self):
        """Migrate RBAC RoleDefinitions to OPA Roles with Policies."""
        from ansible_base.rbac.models import RoleDefinition

        model_to_resource = self._build_resource_model_map()
        role_defs = RoleDefinition.objects.prefetch_related("permissions__content_type").all()

        self.stdout.write(self.style.MIGRATE_HEADING(f"Migrating {role_defs.count()} RBAC RoleDefinitions..."))

        self._rd_to_opa_role = {}
        skipped = 0

        for rd in role_defs:
            # Map permissions to OPA (resource, action) pairs
            resource_actions = set()
            for perm in rd.permissions.all():
                result = self._perm_to_resource_action(perm, model_to_resource)
                if result:
                    resource_actions.add(result)

            if not resource_actions:
                self.stdout.write(f"  SKIP {rd.name}: no mappable permissions")
                skipped += 1
                continue

            # Determine the scope of this role definition
            # - If rd.content_type is set, it applies to a specific model type
            # - The actual object scoping comes from ObjectRole assignments
            opa_role_name = f"rbac:{rd.name}"

            if self.dry_run:
                self.stdout.write(f"  WOULD CREATE Role '{opa_role_name}' with {len(resource_actions)} resource/action pairs")
                self._rd_to_opa_role[rd.pk] = None
                continue

            opa_role, created = Role.objects.get_or_create(
                name=opa_role_name,
                defaults={"description": rd.description or "", "managed": rd.managed},
            )
            self._rd_to_opa_role[rd.pk] = opa_role

            action_str = ", ".join(f"{r}.{a}" for r, a in sorted(resource_actions))
            label = "CREATED" if created else "EXISTS"
            self.stdout.write(f"  {label} Role '{opa_role_name}' -> {action_str}")

        self.stdout.write(f"  {len(self._rd_to_opa_role)} roles mapped, {skipped} skipped")

    def _migrate_assignments(self):
        """Migrate RBAC user/team assignments to OPA group-role assignments."""
        from ansible_base.rbac.models import RoleTeamAssignment, RoleUserAssignment

        model_to_resource = self._build_resource_model_map()

        # --- User assignments ---
        user_assignments = (
            RoleUserAssignment.objects.select_related(
                "user", "role_definition", "content_type", "object_role"
            ).prefetch_related("role_definition__permissions__content_type")
            .all()
        )

        self.stdout.write("")
        self.stdout.write(self.style.MIGRATE_HEADING(f"Migrating {user_assignments.count()} user assignments..."))

        user_created = 0
        user_skipped = 0
        for ua in user_assignments:
            result = self._migrate_single_assignment(
                actor_label=ua.user.username,
                actor_user=ua.user,
                team=None,
                role_definition=ua.role_definition,
                object_id=ua.object_id,
                content_type=ua.content_type,
                model_to_resource=model_to_resource,
            )
            if result:
                user_created += result
            else:
                user_skipped += 1

        self.stdout.write(f"  {user_created} policies created, {user_skipped} skipped")

        # --- Team assignments ---
        team_assignments = (
            RoleTeamAssignment.objects.select_related(
                "team", "role_definition", "content_type", "object_role"
            ).prefetch_related("role_definition__permissions__content_type")
            .all()
        )

        self.stdout.write("")
        self.stdout.write(self.style.MIGRATE_HEADING(f"Migrating {team_assignments.count()} team assignments..."))

        team_created = 0
        team_skipped = 0
        for ta in team_assignments:
            result = self._migrate_single_assignment(
                actor_label=f"team:{ta.team.name}",
                actor_user=None,
                team=ta.team,
                role_definition=ta.role_definition,
                object_id=ta.object_id,
                content_type=ta.content_type,
                model_to_resource=model_to_resource,
            )
            if result:
                team_created += result
            else:
                team_skipped += 1

        self.stdout.write(f"  {team_created} policies created, {team_skipped} skipped")

    def _migrate_single_assignment(self, actor_label, actor_user, team, role_definition, object_id, content_type, model_to_resource):
        """Migrate a single RBAC assignment to OPA.

        For each permission in the role definition, creates an OPA Role with policies
        scoped to the assigned object, then assigns it to the actor's OPA group.

        Returns the number of policies created, or None if skipped.
        """
        rd = role_definition

        # Map permissions
        resource_actions = set()
        for perm in rd.permissions.all():
            result = self._perm_to_resource_action(perm, model_to_resource)
            if result:
                resource_actions.add(result)

        if not resource_actions:
            return None

        # Determine the scope field and value
        if object_id is None:
            # System-wide / singleton role — no object scoping
            # These create policies without field constraints (global access)
            # For now, skip these — they need special handling
            self.stdout.write(f"    SKIP {actor_label} -> {rd.name}: system-wide role (no object scope)")
            return None

        # Resolve the object to determine scoping
        if content_type is None:
            return None

        model_path = f"{content_type.app_label}.{content_type.model}".lower()
        resource_name = model_to_resource.get(model_path)

        if resource_name is None:
            return None

        # Determine scoping: is this an org-level or object-level assignment?
        # If the assigned object IS an organization, scope by organization_id
        # If the assigned object is a resource, scope by id
        org_model_path = getattr(settings, "ANSIBLE_BASE_ORGANIZATION_MODEL", "").lower()
        is_org_assignment = model_path == org_model_path.lower()

        # Build a unique OPA role name for this specific assignment scope
        if is_org_assignment:
            scope_field = "organization_id"
            scope_value = str(object_id)
            scope_label = f"org:{object_id}"
        else:
            scope_field = "id"
            scope_value = str(object_id)
            scope_label = f"{resource_name}:{object_id}"

        opa_role_name = f"rbac:{rd.name}@{scope_label}"

        if self.dry_run:
            actions_str = ", ".join(f"{r}.{a}" for r, a in sorted(resource_actions))
            self.stdout.write(f"    WOULD ASSIGN {actor_label} -> {opa_role_name} ({actions_str})")
            return len(resource_actions)

        # Create or get the scoped OPA Role
        opa_role, _ = Role.objects.get_or_create(
            name=opa_role_name,
            defaults={"description": f"Migrated from RBAC: {rd.name}", "managed": True},
        )

        # Create policies for each (resource, action) pair
        policies_created = 0
        for res, action in resource_actions:
            # For org assignments, create policies for all resources that this
            # role definition's permissions cover (the org scoping applies to child resources)
            if is_org_assignment:
                # If the resource IS the organization model, scope by id not organization_id
                res_model_path = opa_registry.get_resource(res).get("model", "").lower()
                if res_model_path == org_model_path.lower():
                    field = "id"
                else:
                    field = "organization_id"
                value = scope_value
            else:
                # Object-level: only create policy for the specific resource
                if res != resource_name:
                    continue
                field = "id"
                value = scope_value

            _, created = Policy.objects.get_or_create(
                role=opa_role,
                resource=res,
                action=action,
                field_name=field,
                operator="eq",
                value_type="constant",
                defaults={"constant_value": value},
            )
            if created:
                policies_created += 1

        # Get or create the actor's OPA group and assign the role
        if actor_user:
            group_name = f"user:{actor_user.pk}"
            group, _ = OPAGroup.objects.get_or_create(name=group_name, defaults={"managed": True})
            if not group.users.filter(pk=actor_user.pk).exists():
                group.users.add(actor_user)
        elif team:
            group_name = f"team:{team.name}"
            org = getattr(team, "organization", None)
            group, _ = OPAGroup.objects.get_or_create(
                name=group_name,
                defaults={"managed": True, "organization": org},
            )
            # Add all team members to the OPA group
            if hasattr(team, "users"):
                for member in team.users.all():
                    group.users.add(member)
            elif hasattr(team, "member_roles"):
                # Team membership via RBAC member roles
                from ansible_base.rbac.models import ObjectRole
                member_roles = ObjectRole.objects.filter(
                    content_type__model="team",
                    object_id=str(team.pk),
                    role_definition__name__icontains="member",
                )
                for mr in member_roles:
                    for u in mr.users.all():
                        group.users.add(u)

        GroupRoleAssignment.objects.get_or_create(group=group, role=opa_role)

        return policies_created
