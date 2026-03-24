from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Sync policy definitions to OPA and recompute team memberships."

    def handle(self, *args, **options):
        from ansible_base.opa.rego.sync import recompute_team_memberships, sync_policies_to_opa

        self.stdout.write("Syncing policy definitions to OPA...")
        sync_policies_to_opa()
        self.stdout.write(self.style.SUCCESS("Policy sync complete."))

        self.stdout.write("Recomputing team memberships...")
        recompute_team_memberships()
        self.stdout.write(self.style.SUCCESS("Done."))
