from django.db import models
from django.utils.translation import gettext_lazy as _


class Policy(models.Model):
    class Operator(models.TextChoices):
        EQ = "eq", _("Equals")

    class ValueType(models.TextChoices):
        CONSTANT = "constant", _("Constant value")
        PRINCIPAL_USER_ID = "principal_user_id", _("Current user's ID")

    role = models.ForeignKey(
        "dab_opa.Role",
        on_delete=models.CASCADE,
        related_name="policies",
        help_text=_("The role this policy belongs to."),
    )
    resource = models.CharField(
        max_length=255,
        help_text=_("The resource type this policy applies to."),
    )
    action = models.CharField(
        max_length=255,
        help_text=_("The action this policy applies to."),
    )
    field_name = models.CharField(
        max_length=255,
        help_text=_("The field to filter on."),
    )
    operator = models.CharField(
        max_length=20,
        choices=Operator.choices,
        default=Operator.EQ,
        help_text=_("The comparison operator."),
    )
    value_type = models.CharField(
        max_length=30,
        choices=ValueType.choices,
        help_text=_("How the comparison value is determined."),
    )
    constant_value = models.TextField(
        null=True,
        blank=True,
        help_text=_("The constant value to compare against (when value_type is 'constant')."),
    )
    position = models.IntegerField(
        default=0,
        help_text=_("Optional ordering position."),
    )
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    class Meta:
        app_label = "dab_opa"
        ordering = ["role", "resource", "action", "position"]

    def clean(self):
        from ansible_base.lib.opa.validators import validate_policy

        validate_policy(self)

    def __str__(self):
        if self.value_type == self.ValueType.PRINCIPAL_USER_ID:
            return f"{self.resource}.{self.action}: {self.field_name} {self.operator} <principal_user_id>"
        return f"{self.resource}.{self.action}: {self.field_name} {self.operator} {self.constant_value}"
