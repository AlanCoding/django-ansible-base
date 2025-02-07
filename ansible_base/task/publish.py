from dispatcher.utils import serialize_task
from django.db import transaction

from ansible_base.task.models import Task
from ansible_base.task.tasks import run_task_from_queue

# decorator structure is taken from dispatcher.publish


class TaskPublisher:
    def __init__(self, fn):
        self.fn = fn

    @property
    def task_name(self):
        return serialize_task(self.fn)

    def apply_async(self, args=None, kwargs=None):
        # this function may allow additional arguments in the future, but not now
        Task.objects.create(name=self.task_name)

        # pg_notify message (probably) to wake up
        transaction.on_commit(run_task_from_queue.delay)

    def delay(self, *args, **kwargs):
        return self.apply_async(args=args, kwargs=kwargs)


class TaskDecorator:
    def __init__(self, *args, **kwargs):
        # TODO: this will process a task timeout, just not yet set up
        self.args = args
        self.kwargs = kwargs

    def __call__(self, fn):
        publisher = TaskPublisher(fn)

        setattr(fn, 'apply_async', publisher.apply_async)
        setattr(fn, 'delay', publisher.delay)

        return fn


def durable_task():
    return TaskDecorator()
