import sys
import uuid

from django.conf import settings
from django.db import models


class ServiceID(models.Model):
    """
    Provides a globally unique ID for this service.
    """

    id = models.UUIDField(default=uuid.uuid4, primary_key=True, null=False, editable=False)

    def save(self, *args, **kwargs):
        if ServiceID.objects.exists():
            raise RuntimeError("This service already has a ServiceID")

        return super().save()


_service_id = None


def service_id():
    global _service_id
    if not _service_id:
        obj = ServiceID.objects.first()
        if obj is None:
            if settings.DEBUG or any("pytest" in arg for arg in sys.argv):
                obj = ServiceID.objects.create()
            else:
                raise RuntimeError('Expected ServiceID to be created in data migrations but was not found')
        _service_id = str(obj.pk)
    return _service_id
