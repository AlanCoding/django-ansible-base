from dispatcher.main import DispatcherMain

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Runs bug checking sanity checks, gets scale metrics, and recommendations for Role Based Access Control"

    def handle(self, *args, **options):
        dispatcher_config = {
            "producers": {
                "brokers": {
                    "pg_notify": {"conninfo": settings.PG_NOTIFY_DSN_SERVER},
                    # TODO: sanitize or escape channel names on dispatcher side
                    "channels": [
                        "dab_broadcast"
                    ],
                },
                # NOTE: I would prefer to move the activation monitoring
                # from worker to activation, but that is more work
                "scheduled": {},
            },
            "pool": {"max_workers": 4},
        }

        DispatcherMain()