import logging

from dispatcher.factories import get_control_from_settings
from dispatcher.publish import task as dispatcher_task
from dispatcher.utils import resolve_callable
from django.conf import settings
from django.db import transaction
from django.utils.timezone import now, timedelta

from ansible_base.task.models import TASK_STATES, Task

logger = logging.getLogger(__name__)


@dispatcher_task(queue=settings.DAB_TASK_ADMIN_QUEUE, bind=True)
def run_task_from_queue(dispatcher):
    with transaction.atomic():
        db_task = Task.objects.filter(state=TASK_STATES.WAITING, queue__in=settings.DAB_TASK_LISTEN_QUEUES).select_for_update().first()
        if db_task:
            db_task.state = TASK_STATES.RUNNING
            db_task.started_at = now()
            db_task.wrapper_uuid = str(dispatcher.uuid)
            db_task.save(update_fields=['state', 'started_at', 'wrapper_uuid'])
        else:
            return

    # for responsiveness with bursts of tasks
    if Task.objects.filter(state=TASK_STATES.WAITING).exists():
        run_task_from_queue.delay()

    try:
        task_callable = resolve_callable(db_task.name)
        task_callable(*db_task.args, **db_task.kwargs)
    except Exception:
        logger.exception(f'Failed to run and complete {db_task.name}')

    db_task.delete()


@dispatcher_task(queue=settings.DAB_TASK_ADMIN_QUEUE)
def manage_lost_tasks(grace_period: int = 10):
    cutoff_time = now() - timedelta(minutes=grace_period)
    for db_task in Task.objects.filter(state=TASK_STATES.RUNNING, started_at__lt=cutoff_time, queue__in=settings.DAB_TASK_LISTEN_QUEUES).iterator():
        ctl = get_control_from_settings(default_publish_channel=settings.DAB_TASK_ADMIN_QUEUE)

        running_tasks = ctl.control_with_reply('running', data={'uuid': str(db_task.wrapper_uuid)})

        found = False
        for server_reply in running_tasks:
            for worker_id, task_data in server_reply:
                if task_data.get('uuid') == str(db_task.wrapper_uuid):
                    found = True
                    break
            if found:
                break

        if not found:
            # TODO: feature of retry policy
            try:
                with transaction.atomic():
                    db_task = Task.objects.select_for_update().get(uuid=db_task.uuid)
                    logger.warning(f'Could not find task {db_task.name} {db_task.wrapper_uuid}, deleting entry')
                    db_task.delete()
            except Task.DoesNotExist:
                logger.debug(f'task {db_task.name} uuid={db_task.uuid} already deleted, doing nothing')
        else:
            delta = now() - db_task.started_at
            logger.info(f'Noticed {db_task.name} {db_task.wrapper_uuid} running for {delta} seconds, seems to be fine')
