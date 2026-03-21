from django.conf import settings
from django.db import models
from django.utils.translation import gettext_lazy as _


class OPAGroup(models.Model):
    name = models.CharField(
        max_length=512,
        help_text=_("The name of this OPA group."),
    )
    organization = models.ForeignKey(
        settings.ANSIBLE_BASE_ORGANIZATION_MODEL,
        on_delete=models.CASCADE,
        related_name="opa_groups",
        null=True,
        blank=True,
        help_text=_("The organization this group belongs to."),
    )
    users = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name="dab_opa_groups",
        blank=True,
        help_text=_("Users in this OPA group."),
    )
    managed = models.BooleanField(
        default=False,
        help_text=_("Whether this group is system-managed (e.g. per-user groups)."),
    )
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "dab_opa"
        ordering = ["id"]
        verbose_name = "OPA Group"
        verbose_name_plural = "OPA Groups"

    def __str__(self):
        return self.name
