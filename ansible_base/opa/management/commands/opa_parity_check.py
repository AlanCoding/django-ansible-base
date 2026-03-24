from django.apps import apps as django_apps
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from ansible_base.opa.evaluator import local_filter_queryset
from ansible_base.opa.queryset import filter_queryset_for_user, get_opa_scope
from ansible_base.opa.registry import opa_registry


class Command(BaseCommand):
    help = "Run parity checks between OPA and local evaluator for all users and registered resources."

    def add_arguments(self, parser):
        parser.add_argument("--user", type=str, help="Check a single username instead of all users.")
        parser.add_argument("--resource", type=str, help="Check a single resource instead of all resources.")
        parser.add_argument("--no-sync", action="store_true", help="(Deprecated, no-op) Sync is no longer needed.")
        parser.add_argument("--verbose", action="store_true", help="Show OPA clauses for each check.")

    def handle(self, *args, **options):
        User = get_user_model()

        # Determine users to check
        if options["user"]:
            users = User.objects.filter(username=options["user"])
            if not users.exists():
                self.stderr.write(self.style.ERROR(f"User '{options['user']}' not found."))
                return
        else:
            users = User.objects.all().order_by("username")

        # Determine resources to check
        if options["resource"]:
            resource_name = options["resource"]
            try:
                opa_registry.get_resource(resource_name)
            except ValueError as e:
                self.stderr.write(self.style.ERROR(str(e)))
                return
            resources = {resource_name: opa_registry.get_resource(resource_name)}
        else:
            resources = opa_registry.resources

        self.stdout.write(f"Checking {users.count()} users x {len(resources)} resources")
        self.stdout.write("")

        all_match = True
        mismatches = []
        checks = 0

        for user in users:
            user_header_printed = False

            for resource_name, resource_def in resources.items():
                model_cls = opa_registry.get_model(resource_name)
                base_qs = model_cls.objects.all()

                if not base_qs.exists():
                    continue

                for action in resource_def["actions"]:
                    checks += 1
                    opa_qs = filter_queryset_for_user(base_qs, user, action)
                    local_qs = local_filter_queryset(base_qs, user, action)
                    opa_pks = set(opa_qs.values_list("pk", flat=True))
                    local_pks = set(local_qs.values_list("pk", flat=True))

                    match = opa_pks == local_pks

                    if not match:
                        all_match = False
                        mismatches.append((user.username, resource_name, action, opa_pks, local_pks))

                    # Only print per-user details if there's something to show
                    has_access = len(opa_pks) > 0
                    if not match or has_access or options["verbose"]:
                        if not user_header_printed:
                            su_tag = " (superuser)" if user.is_superuser else ""
                            self.stdout.write(f"  {user.username} (pk={user.pk}){su_tag}:")
                            user_header_printed = True

                        label = self.style.SUCCESS("MATCH") if match else self.style.ERROR("MISMATCH")
                        count_str = f"{len(opa_pks)}/{base_qs.count()} objects"
                        self.stdout.write(f"    {resource_name}.{action:8s} {label}  {count_str}")

                        if not match:
                            only_opa = opa_pks - local_pks
                            only_local = local_pks - opa_pks
                            if only_opa:
                                self.stdout.write(f"      OPA only: pks={only_opa}")
                            if only_local:
                                self.stdout.write(f"      Local only: pks={only_local}")

                        if options["verbose"] and not user.is_superuser and has_access:
                            scope = get_opa_scope(user, resource_name, action)
                            clauses_str = "; ".join(
                                f"{c['field_name']} {c['operator']} {c['value']}"
                                for c in scope["clauses"]
                            ) or "(empty)"
                            self.stdout.write(f"      clauses: {clauses_str}")

            if user_header_printed:
                self.stdout.write("")

        self.stdout.write(f"Ran {checks} checks.")
        if all_match:
            self.stdout.write(self.style.SUCCESS("All parity checks passed!"))
        else:
            self.stdout.write(self.style.ERROR(f"{len(mismatches)} parity failures:"))
            for uname, resource, action, opa, local in mismatches:
                self.stdout.write(f"  {uname} {resource}.{action}: OPA={opa} Local={local}")
