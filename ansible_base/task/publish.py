from dispatcher.utils import serialize_task
from django.conf import settings
from django.db import transaction

from ansible_base.task.models import Task
from ansible_base.task.tasks import run_task_from_queue

# decorator structure is taken from dispatcher.publish


class TaskPublisher:
    def __init__(self, fn, queue=None):
        self.fn = fn
        self.queue = queue

    @property
    def task_name(self):
        return serialize_task(self.fn)

    def submit_wrapper_task(self):
        run_task_from_queue.apply_async(queue=self.queue)

    def apply_async(self, args=None, kwargs=None):
        # this function may allow additional arguments in the future, but not now
        if self.queue is None:
            queue = settings.DAB_TASK_ADMIN_QUEUE
        else:
            queue = self.queue
        Task.objects.create(name=self.task_name, args=args, kwargs=kwargs, queue=queue)

        # pg_notify message (probably) to wake up
        transaction.on_commit(self.submit_wrapper_task)

    def delay(self, *args, **kwargs):
        return self.apply_async(args=args, kwargs=kwargs)


class TaskDecorator:
    def __init__(self, queue=None):
        self.queue = queue

    def __call__(self, fn):
        publisher = TaskPublisher(fn, queue=self.queue)

        setattr(fn, 'apply_async', publisher.apply_async)
        setattr(fn, 'delay', publisher.delay)

        return fn


def durable_task(queue=None):
    return TaskDecorator(queue=queue)
