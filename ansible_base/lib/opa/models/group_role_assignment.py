from django.db import models
from django.utils.translation import gettext_lazy as _


class GroupRoleAssignment(models.Model):
    group = models.ForeignKey(
        "dab_opa.OPAGroup",
        on_delete=models.CASCADE,
        related_name="role_assignments",
        help_text=_("The group receiving this role."),
    )
    role = models.ForeignKey(
        "dab_opa.Role",
        on_delete=models.CASCADE,
        related_name="group_assignments",
        help_text=_("The role being assigned."),
    )
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "dab_opa"
        unique_together = [("group", "role")]
        ordering = ["id"]

    def __str__(self):
        return f"{self.group} -> {self.role}"
