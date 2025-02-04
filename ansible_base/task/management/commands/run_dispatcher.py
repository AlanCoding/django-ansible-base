import logging

from dispatcher import run_service
from django.core.cache import cache
from django.core.management.base import BaseCommand
from django.db import connection

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Runs bug checking sanity checks, gets scale metrics, and recommendations for Role Based Access Control"

    def handle(self, *args, **options):
        # Borrowed from eda-server, ensure the database connection is closed
        connection.close()
        cache.close()

        # Configuration is already handled in app .ready method
        run_service()
