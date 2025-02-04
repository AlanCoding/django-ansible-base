from types import SimpleNamespace
from uuid import uuid4

from django.db import models
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _

# NOTE: tasks are not registered in the database, but in a dispatcher registry

TASK_STATES = SimpleNamespace(
    WAITING="waiting",
    # SKIPPED="skipped",
    RUNNING="running",
    COMPLETED="completed",
    FAILED="failed",
    # CANCELED="canceled",
    # CANCELING="canceling",
)


class Task(models.Model):
    """
    Corresponds to a call of a task, as a higher-level abstraction around the dispatcher.
    Loosely modeled after pulpcore.Task
    """

    uuid = models.UUIDField(primary_key=True, default=uuid4, editable=False, help_text=_('Original dispatcher UUID generated at time of task publishing'))
    # TODO: change back to UUIDField, workaround dispatcher using non-UUID uuids for now
    # null=True
    wrapper_uuid = models.CharField(
        blank=True, default='', max_length=40, editable=False, help_text=_('Adopted UUID of DAB task app wrapper, attached when background service starts task')
    )
    state = models.CharField(
        choices=[(s, s.title()) for s in sorted(vars(TASK_STATES).values())],
        default=TASK_STATES.WAITING,
        max_length=15,
        help_text=_('Choices of this field track with acknowledgement and completion of a task'),
    )
    name = models.TextField(help_text=_('Importable path for class or method'))
    queue = models.TextField(default='', help_text=_('The work queue this task is submitted to, only nodes listening to this queue may process the task'))

    args = models.JSONField(default=dict, null=False, blank=True, help_text=_("The arguments for the task run."))
    kwargs = models.JSONField(default=dict, null=False, blank=True, help_text=_("The keyword arguments for the task run."))

    created = models.DateTimeField(
        auto_now_add=True, help_text=_('Time the publisher (submitter) of this task call created it, approximately the time of submission as well')
    )
    # pulp has unblocking logic, like unblocked_at, we have no plans for that here
    started_at = models.DateTimeField(null=True, help_text=_('Time of acknowledgement, also approximately the time the task starts'))
    finished_at = models.DateTimeField(null=True, help_text=_('Time task is cleared (whether failed or succeeded), may be unused if set to auto-delete'))

    def mark_completed(self):
        self.state = TASK_STATES.COMPLETED
        self.finished_at = now()

    def mark_failed(self):
        self.state = TASK_STATES.FAILED
        self.finished_at = now()
