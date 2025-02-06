import logging

from dispatcher.utils import resolve_callable
from dispatcher.publish import task
from django.db import transaction

from ansible_base.task.models import TASK_STATES, Task

logger = logging.getLogger(__name__)


@task(queue='dab_broadcast')
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


# TODO: Add a "reaper" fallback task, this is currently blocked on dispatcher issue
# https://github.com/ansible/dispatcher/issues/6
# When run_task_from_queue starts the task, the uuid needs to be setup to be discoverable
# this fallback method will query for tasks that are older than a certain grace period
# later improvement: look for tasks older that the task timeout plus a grace period
# these tasks are in arrears
# For each task in arrears, we will:
# 1. obtain a row-level lock for that task
# 2. send a roll-call message looking for its uuid
# 3. if we get no answer to the roll-call, the task status is changed to lost
# 4. dependent on policies defined in settings, we may re-submit the task up to a retry count
# 5. if retry count is exhausted, task is failed
