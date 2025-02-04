import time
from uuid import UUID

from ansible_base.task.publish import durable_task
from test_app.models import UUIDModel


@durable_task()
def hello_world():
    print('hello world')


@durable_task(queue='dab_task_tasks')
def hello_world_other_queue():
    print('hello world, sent from test_app_tasks queue')


@durable_task()
def create_uuid_entry(uuid: UUID):
    UUIDModel.objects.create(id=uuid)


@durable_task()
def sleep(seconds=2):
    print(f'about to sleep for {seconds} seconds')
    time.sleep(seconds)
    print(f'finished sleeping for {seconds} seconds')
