from uuid import uuid4
import time

import pytest

from ansible_base.task import get_config

from test_app.tasks import create_uuid_entry
from test_app.models import UUIDModel


@pytest.mark.django_db
def test_run_task(dispatcher_subprocess):
    with dispatcher_subprocess(get_config()) as server:
        my_uuid = str(uuid4())
        create_uuid_entry.delay(uuid=my_uuid)

        for i in range(20):
            if UUIDModel.objects.filter(id=my_uuid).exists():
                break
            time.sleep(0.05)
        else:
            assert f'Task never inserted UUID entry with {my_uuid}'
