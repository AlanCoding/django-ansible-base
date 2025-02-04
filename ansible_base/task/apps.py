from django.apps import AppConfig


class TaskConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ansible_base.task'
    label = 'dab_tas'
    verbose_name = 'DAB tasking system'
