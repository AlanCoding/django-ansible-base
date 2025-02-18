import asyncio
import logging

from dispatcher.main import DispatcherMain

from ansible_base.task import get_config

from django.core.management.base import BaseCommand
from django.db import connection
from django.core.cache import cache

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Runs bug checking sanity checks, gets scale metrics, and recommendations for Role Based Access Control"

    def handle(self, *args, **options):
        dispatcher_config = get_config()

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
