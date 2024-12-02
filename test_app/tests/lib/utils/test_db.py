import threading
import time

import pytest
from django.db import connection

from ansible_base.lib.utils.db import advisory_lock, migrations_are_complete


@pytest.mark.django_db
def test_migrations_are_complete():
    "If you are running tests, migrations (test database) should be complete"
    assert migrations_are_complete()


@pytest.mark.django_db
def test_get_unclaimed_lock():
    with advisory_lock('test_get_unclaimed_lock'):
        pass


def background_task(django_db_blocker):
    # HACK: as a thread the pytest.mark.django_db will not work
    django_db_blocker.unblock()
    with advisory_lock('background_task_lock'):
        time.sleep(0.1)


@pytest.mark.django_db
def test_determine_lock_is_held(django_db_blocker):
    if connection.vendor == 'sqlite':
        pytest.skip('Advisory lock is not written for sqlite')
    thread = threading.Thread(target=background_task, args=(django_db_blocker,))
    thread.start()
    for _ in range(5):
        with advisory_lock('background_task_lock', wait=False) as held:
            if held is False:
                break
        time.sleep(0.01)
    else:
        raise RuntimeError('Other thread never obtained lock')
    thread.join()
