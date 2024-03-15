from django.contrib.contenttypes.models import ContentType
from django.db import models


class DABPermission(models.Model):
    "This is a minimal copy of auth.Permission for internal use"

    name = models.CharField("name", max_length=255)
    content_type = models.ForeignKey(ContentType, models.CASCADE, verbose_name="content type")
    codename = models.CharField("codename", max_length=100)

    class Meta:
        verbose_name = "permission"
        verbose_name_plural = "permissions"
        unique_together = [["content_type", "codename"]]
        ordering = ["content_type__model", "codename"]

    def __str__(self):
        return f"<{self.__class__.__name__}: {self.codename}>"
