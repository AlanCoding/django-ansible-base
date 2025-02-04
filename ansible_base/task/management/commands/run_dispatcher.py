import asyncio
import logging

from dispatcher.main import DispatcherMain

from ansible_base.lib.utils.db import get_pg_notify_params

from django.core.management.base import BaseCommand
from django.db import connection
from django.core.cache import cache

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Runs bug checking sanity checks, gets scale metrics, and recommendations for Role Based Access Control"

    def handle(self, *args, **options):
        psycopg_params = get_pg_notify_params()
        psycopg_params.pop('autocommit')  # dispatcher automatically adds this, causes error, TODO: need pre-check
        psycopg_params.pop('cursor_factory')
        psycopg_params.pop('context')  # TODO: remove in inner method, makes non-async, not good

        dispatcher_config = {
            "producers": {
                "brokers": {
                    "pg_notify": psycopg_params,
                    "channels": ["dab_broadcast"],
                },
                "scheduled": {},
            },
            "pool": {"max_workers": 4},  # TODO: to settings
        }

        loop = asyncio.get_event_loop()
        dispatcher = DispatcherMain(dispatcher_config)

        # Borrowed from eda-server, ensure the database connection is closed
        connection.close()
        cache.close()
        try:
            loop.run_until_complete(dispatcher.main())
        except KeyboardInterrupt:
            logger.info("run_worker_dispatch entry point leaving")
        finally:
            loop.close()
