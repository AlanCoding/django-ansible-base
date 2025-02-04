from django.conf import settings

from ansible_base.lib.utils.db import get_pg_notify_params


def get_config() -> dict:
    "Returns dispatcher config from what is in Django settings"
    psycopg_params = get_pg_notify_params()

    return {
        "version": 2,
        "brokers": {
            "pg_notify": {
                "config": psycopg_params,  # used to create the service async connection
                "sync_connection_factory": "ansible_base.lib.utils.db.psycopg_connection_from_django",
                "channels": settings.DAB_TASK_LISTEN_QUEUES,
                # The default publish channel allows using .delay without more arguments
                # this may still have task-specific overrides
                "default_publish_channel": settings.DAB_TASK_ADMIN_QUEUE,
            }
        },
        "producers": {
            "ScheduledProducer": {
                "task_schedule": {
                    "ansible_base.task.tasks.run_task_from_queue": {"schedule": 60},
                    "ansible_base.task.tasks.manage_lost_tasks": {"schedule": 60 * 10},
                }
            },
        },
        "pool": {"max_workers": settings.DAB_TASK_MAX_WORKERS},
    }
