from django.db import transaction

from dispatcher.utils import serialize_task

from ansible_base.task.tasks import run_task_from_queue
from ansible_base.task.models import Task

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

        transaction.on_commit(run_task_from_queue.delay)

    def delay(self, *args, **kwargs):
        return self.apply_async(args=args, kwargs=kwargs)


class TaskDecorator:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def __call__(self, fn):
        publisher = TaskPublisher(fn)

        setattr(fn, 'apply_async', publisher.apply_async)
        setattr(fn, 'delay', publisher.delay)

        return fn
