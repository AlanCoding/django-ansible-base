from django.db import models
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext_lazy as _


class DABPermission(models.Model):
    "This is a minimal copy of auth.Permission for internal use"

    name = models.CharField("name", max_length=255, help_text=_("The name of this permission."))
    content_type = models.ForeignKey(ContentType, models.CASCADE, verbose_name="content type", help_text=_("The content type this permission will apply to."))
    codename = models.CharField(
        "codename",
        max_length=100,
        help_text=_(
            "".join(
                [
                    "A codename for the permission, in the format {action}_{model_name}. ",
                    "Where action is typically the view set action (view/list/etc) from Django rest framework.",
                ]
            )
        ),
    )

    class Meta:
        app_label = 'dab_rbac'
        verbose_name = "permission"
        verbose_name_plural = "permissions"
        unique_together = [["content_type", "codename"]]
        ordering = ["content_type__model", "codename"]

    def __str__(self):
        return f"<{self.__class__.__name__}: {self.codename}>"
