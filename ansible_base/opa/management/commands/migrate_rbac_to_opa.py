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
        parser.add_argument("--verify", action="store_true", help="After migration, compare RBAC vs OPA effective permissions for all users.")

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

        if options["verify"] and not self.dry_run:
            self.stdout.write("")
            self._verify_parity()

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
            # These create policies that grant access to ALL objects of each resource type
            return self._migrate_global_assignment(
                actor_label=actor_label,
                actor_user=actor_user,
                team=team,
                role_definition=rd,
                resource_actions=resource_actions,
            )

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
                constant_value=value,
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

    def _migrate_global_assignment(self, actor_label, actor_user, team, role_definition, resource_actions):
        """Migrate a system-wide (global/singleton) role assignment.

        Global roles have no object_id — they grant access to ALL objects of
        matching resource types. Since we only support eq operator, we expand
        global access into per-org or per-object policies for all existing data.
        """
        rd = role_definition
        opa_role_name = f"rbac:{rd.name}@global"
        org_model_path = getattr(settings, "ANSIBLE_BASE_ORGANIZATION_MODEL", "").lower()

        if self.dry_run:
            actions_str = ", ".join(f"{r}.{a}" for r, a in sorted(resource_actions))
            self.stdout.write(f"    WOULD ASSIGN {actor_label} -> {opa_role_name} (global: {actions_str})")
            return len(resource_actions)

        opa_role, _ = Role.objects.get_or_create(
            name=opa_role_name,
            defaults={"description": f"Migrated global role: {rd.name}", "managed": True},
        )

        # For global roles, create policies scoped to each existing organization
        # plus policies for non-org-scoped resources scoped to each existing object
        from django.apps import apps as django_apps

        policies_created = 0
        for res, action in resource_actions:
            res_def = opa_registry.get_resource(res)
            res_model_path = res_def.get("model", "").lower()
            model_cls = django_apps.get_model(res_def["model"])

            if res_model_path == org_model_path:
                # The resource IS the organization — scope by id for each org
                for org_pk in model_cls.objects.values_list("pk", flat=True):
                    _, created = Policy.objects.get_or_create(
                        role=opa_role,
                        resource=res,
                        action=action,
                        field_name="id",
                        operator="eq",
                        value_type="constant",
                        constant_value=str(org_pk),
                    )
                    if created:
                        policies_created += 1
            elif hasattr(model_cls, "organization_id") or hasattr(model_cls, "organization"):
                # Org-scoped resource — create policies for each org
                org_model = django_apps.get_model(settings.ANSIBLE_BASE_ORGANIZATION_MODEL)
                for org_pk in org_model.objects.values_list("pk", flat=True):
                    _, created = Policy.objects.get_or_create(
                        role=opa_role,
                        resource=res,
                        action=action,
                        field_name="organization_id",
                        operator="eq",
                        value_type="constant",
                        constant_value=str(org_pk),
                    )
                    if created:
                        policies_created += 1
            else:
                # Non-org-scoped resource — create policies for each existing object
                for obj_pk in model_cls.objects.values_list("pk", flat=True):
                    _, created = Policy.objects.get_or_create(
                        role=opa_role,
                        resource=res,
                        action=action,
                        field_name="id",
                        operator="eq",
                        value_type="constant",
                        constant_value=str(obj_pk),
                    )
                    if created:
                        policies_created += 1

        # Assign to actor's group
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

        GroupRoleAssignment.objects.get_or_create(group=group, role=opa_role)

        self.stdout.write(f"    GLOBAL {actor_label} -> {opa_role_name} ({policies_created} policies)")
        return policies_created

    def _verify_parity(self):
        """Compare RBAC and OPA effective permissions for all users."""
        from ansible_base.opa.evaluator import local_filter_queryset
        from ansible_base.rbac import permission_registry

        User = get_user_model()
        users = User.objects.all().order_by("username")

        self.stdout.write(self.style.MIGRATE_HEADING("Verifying RBAC vs OPA parity..."))

        mismatches = []
        checks = 0

        for user in users:
            for resource_name, resource_def in opa_registry.resources.items():
                model_cls = opa_registry.get_model(resource_name)
                base_qs = model_cls.objects.all()

                if not base_qs.exists():
                    continue

                # Check if model is registered in RBAC
                if not permission_registry.is_registered(model_cls):
                    continue

                for action in resource_def["actions"]:
                    checks += 1

                    # OPA result (local evaluator, no OPA server needed)
                    opa_qs = local_filter_queryset(base_qs, user, action)
                    opa_pks = set(opa_qs.values_list("pk", flat=True))

                    # RBAC result via access_qs
                    rbac_pks = self._rbac_accessible_pks(user, model_cls, action, base_qs)

                    if opa_pks != rbac_pks:
                        mismatches.append((user.username, resource_name, action, opa_pks, rbac_pks))
                        only_opa = opa_pks - rbac_pks
                        only_rbac = rbac_pks - opa_pks
                        self.stdout.write(
                            self.style.ERROR(
                                f"  MISMATCH {user.username} {resource_name}.{action}: "
                                f"OPA-only={only_opa or set()} RBAC-only={only_rbac or set()}"
                            )
                        )

        self.stdout.write(f"\nRan {checks} parity checks.")
        if mismatches:
            self.stdout.write(self.style.ERROR(f"{len(mismatches)} mismatches found."))
        else:
            self.stdout.write(self.style.SUCCESS("All parity checks passed!"))

    def _rbac_accessible_pks(self, user, model_cls, action, base_qs):
        """Get the set of PKs a user can access via RBAC for a given action."""
        if user.is_superuser:
            return set(base_qs.values_list("pk", flat=True))

        # Map OPA action back to Django permission codename
        reverse_action_map = {v: k for k, v in ACTION_PREFIX_MAP.items()}
        django_action = reverse_action_map.get(action)
        if django_action is None:
            return set()

        # Use RBAC's access_qs descriptor for queryset-based evaluation
        try:
            rbac_qs = model_cls.access_qs(user, django_action, queryset=base_qs)
            return set(rbac_qs.values_list("pk", flat=True))
        except Exception:
            return set()
