from dispatcher.config import setup
from django.apps import AppConfig

from ansible_base.task.config import get_config


class TaskConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ansible_base.task'
    label = 'dab_tas'
    verbose_name = 'DAB tasking system'

    def ready(self):
        # Set up dispatcher
        setup(get_config())
