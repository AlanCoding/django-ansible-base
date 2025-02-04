import logging

from dispatcher.utils import resolve_callable
from django.db import transaction

from ansible_base.task.models import TASK_STATES, Task

logger = logging.getLogger(__name__)


def run_task_from_queue():
    with transaction.atomic():
        task = Task.objects.filter(state=TASK_STATES.WAITING).select_for_update().first()
        if task:
            task.mark_ack()
        else:
            return

    # for responsiveness with bursts of tasks
    if Task.objects.filter(state=TASK_STATES.WAITING).exists():
        run_task_from_queue.delay()

    try:
        task_callable = resolve_callable(task.name)
        task_callable()
    except Exception:
        logger.traceback(f'Failed to run and complete {task.name}')

    task.delete()
