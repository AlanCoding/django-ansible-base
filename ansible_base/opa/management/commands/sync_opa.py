from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Force-regenerate OPA policy data and push to OPA server."

    def handle(self, *args, **options):
        from ansible_base.opa.rego.sync import sync_to_opa

        self.stdout.write("Generating and syncing OPA policy data...")
        sync_to_opa(debounce_seconds=0)
        self.stdout.write(self.style.SUCCESS("OPA sync complete."))
