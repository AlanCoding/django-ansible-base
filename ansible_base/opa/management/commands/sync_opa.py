from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Check OPA server health and recompute team memberships."

    def handle(self, *args, **options):
        from ansible_base.opa.client import OPAClient
        from ansible_base.opa.rego.sync import recompute_team_memberships

        client = OPAClient()
        try:
            client.health()
            self.stdout.write(self.style.SUCCESS("OPA server is healthy."))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"OPA server health check failed: {e}"))

        self.stdout.write("Recomputing team memberships...")
        recompute_team_memberships()
        self.stdout.write(self.style.SUCCESS("Done."))
