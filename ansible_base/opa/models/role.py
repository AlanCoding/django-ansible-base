from django.db import models
from django.utils.translation import gettext_lazy as _


class Role(models.Model):
    name = models.CharField(
        max_length=512,
        unique=True,
        help_text=_("The name of this role."),
    )
    description = models.TextField(
        blank=True,
        default="",
        help_text=_("A description of what this role grants."),
    )
    managed = models.BooleanField(
        default=False,
        help_text=_("Whether this role is system-managed."),
    )
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "dab_opa"
        ordering = ["id"]

    def __str__(self):
        return self.name
