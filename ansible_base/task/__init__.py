from ansible_base.lib.utils.db import get_pg_notify_params


def get_config():
    psycopg_params = get_pg_notify_params()
    psycopg_params.pop('autocommit')  # dispatcher automatically adds this, causes error, TODO: need pre-check
    psycopg_params.pop('cursor_factory')
    psycopg_params.pop('context')  # TODO: remove in inner method, makes non-async, not good

    return {
        "producers": {
            "brokers": {
                "pg_notify": psycopg_params,
                "channels": ["dab_broadcast"],
            },
            "scheduled": {},
        },
        "pool": {"max_workers": 4},  # TODO: to settings
    }
