import json
import logging

from django import forms
from django.contrib import admin, messages
from django.http import JsonResponse
from django.urls import path, reverse
from django.utils.html import format_html

from ansible_base.opa.models import GroupRoleAssignment, OPAGroup, Policy, Role
from ansible_base.opa.registry import opa_registry

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Policy form with registry-driven dropdowns
# ---------------------------------------------------------------------------


def _resource_choices():
    """Build choices for the resource dropdown from the OPA registry."""
    choices = [("", "---------")]
    try:
        for name in sorted(opa_registry.resources.keys()):
            choices.append((name, name))
    except Exception:
        pass
    return choices


def _action_choices():
    """Build all possible action choices (filtered by JS on the client)."""
    choices = [("", "---------")]
    seen = set()
    try:
        for resource_def in opa_registry.resources.values():
            for action in resource_def["actions"]:
                if action not in seen:
                    choices.append((action, action))
                    seen.add(action)
    except Exception:
        pass
    return choices


def _field_choices():
    """Build all possible field choices (filtered by JS on the client)."""
    choices = [("", "---------")]
    seen = set()
    try:
        # Shared fields
        for name in opa_registry.shared_fields:
            if name not in seen:
                choices.append((name, name))
                seen.add(name)
        # Resource-specific fields
        for resource_def in opa_registry.resources.values():
            for name in resource_def.get("fields", {}):
                if name not in seen:
                    choices.append((name, name))
                    seen.add(name)
    except Exception:
        pass
    return choices


class PolicyForm(forms.ModelForm):
    resource = forms.ChoiceField(choices=_resource_choices)
    action = forms.ChoiceField(choices=_action_choices)
    field_name = forms.ChoiceField(choices=_field_choices)

    class Meta:
        model = Policy
        fields = [
            "role",
            "resource",
            "action",
            "field_name",
            "operator",
            "value_type",
            "constant_value",
            "position",
        ]

    class Media:
        js = ("opa/admin/policy_form.js",)

    def clean(self):
        cleaned = super().clean()
        # Run model-level validation
        instance = self.instance or Policy()
        for k, v in cleaned.items():
            if hasattr(instance, k):
                setattr(instance, k, v)

        from ansible_base.opa.validators import validate_policy

        try:
            validate_policy(instance)
        except Exception as e:
            raise forms.ValidationError(str(e))

        return cleaned


class PolicyInlineForm(PolicyForm):
    """Same as PolicyForm but without the role field (it's implicit from the parent)."""

    class Meta(PolicyForm.Meta):
        fields = [f for f in PolicyForm.Meta.fields if f != "role"]


# ---------------------------------------------------------------------------
# Inline for policies within Role admin
# ---------------------------------------------------------------------------


class PolicyInline(admin.TabularInline):
    model = Policy
    form = PolicyInlineForm
    extra = 1
    fields = [
        "resource",
        "action",
        "field_name",
        "operator",
        "value_type",
        "constant_value",
        "object_link",
        "position",
    ]
    readonly_fields = ["object_link"]

    def object_link(self, obj):
        """Show a link to the referenced object if constant_value is a PK."""
        if not obj.pk or obj.value_type != "constant" or not obj.constant_value:
            return "-"
        return _render_object_link(obj.resource, obj.field_name, obj.constant_value)

    object_link.short_description = "Referenced Object"


# ---------------------------------------------------------------------------
# Inline for assignments within Group or Role admin
# ---------------------------------------------------------------------------


class GroupRoleAssignmentInline(admin.TabularInline):
    model = GroupRoleAssignment
    extra = 1
    autocomplete_fields = ["role", "group"]


class GroupRoleAssignmentByGroupInline(admin.TabularInline):
    model = GroupRoleAssignment
    fk_name = "group"
    extra = 1
    autocomplete_fields = ["role"]
    fields = ["role", "created"]
    readonly_fields = ["created"]


class GroupRoleAssignmentByRoleInline(admin.TabularInline):
    model = GroupRoleAssignment
    fk_name = "role"
    extra = 1
    autocomplete_fields = ["group"]
    fields = ["group", "created"]
    readonly_fields = ["created"]


# ---------------------------------------------------------------------------
# Role admin
# ---------------------------------------------------------------------------


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ["name", "managed", "policy_count", "group_count", "modified"]
    list_filter = ["managed"]
    search_fields = ["name", "description"]
    readonly_fields = ["created", "modified", "policy_summary"]
    inlines = [PolicyInline, GroupRoleAssignmentByRoleInline]

    fieldsets = [
        (None, {"fields": ["name", "description", "managed"]}),
        ("Info", {"fields": ["created", "modified", "policy_summary"]}),
    ]

    def policy_count(self, obj):
        return obj.policies.count()

    policy_count.short_description = "Policies"

    def group_count(self, obj):
        return obj.group_assignments.count()

    group_count.short_description = "Groups"

    def policy_summary(self, obj):
        policies = obj.policies.all()
        if not policies:
            return "No policies defined."
        rows = []
        for p in policies:
            ref = _render_object_link(p.resource, p.field_name, p.constant_value)
            rows.append(
                f"<tr><td>{p.resource}</td><td>{p.action}</td>"
                f"<td>{p.field_name} {p.operator}</td>"
                f"<td>{p.constant_value or '<i>principal_user_id</i>'}</td>"
                f"<td>{ref}</td></tr>"
            )
        table = (
            '<table style="border-collapse:collapse">'
            "<tr><th>Resource</th><th>Action</th><th>Filter</th><th>Value</th><th>Object</th></tr>"
            + "".join(rows)
            + "</table>"
        )
        return format_html(table)

    policy_summary.short_description = "Policy Summary"


# ---------------------------------------------------------------------------
# Policy admin (standalone)
# ---------------------------------------------------------------------------


@admin.register(Policy)
class PolicyAdmin(admin.ModelAdmin):
    form = PolicyForm
    list_display = [
        "id",
        "role_link",
        "resource",
        "action",
        "field_name",
        "operator",
        "value_display",
        "object_link",
    ]
    list_filter = ["resource", "action", "value_type"]
    search_fields = ["role__name", "resource", "constant_value"]
    autocomplete_fields = ["role"]
    readonly_fields = ["created", "modified", "object_link"]

    fieldsets = [
        ("Scope", {"fields": ["role", "resource", "action"]}),
        ("Filter", {"fields": ["field_name", "operator", "value_type", "constant_value"]}),
        ("Object Reference", {"fields": ["object_link"]}),
        ("Meta", {"fields": ["position", "created", "modified"]}),
    ]

    def role_link(self, obj):
        url = reverse("admin:dab_opa_role_change", args=[obj.role_id])
        return format_html('<a href="{}">{}</a>', url, obj.role.name)

    role_link.short_description = "Role"
    role_link.admin_order_field = "role__name"

    def value_display(self, obj):
        if obj.value_type == "principal_user_id":
            return format_html("<em>current user</em>")
        return obj.constant_value

    value_display.short_description = "Value"

    def object_link(self, obj):
        if not obj.pk or obj.value_type != "constant" or not obj.constant_value:
            return "-"
        return _render_object_link(obj.resource, obj.field_name, obj.constant_value)

    object_link.short_description = "Referenced Object"


# ---------------------------------------------------------------------------
# OPAGroup admin
# ---------------------------------------------------------------------------


@admin.register(OPAGroup)
class OPAGroupAdmin(admin.ModelAdmin):
    list_display = ["name", "organization", "managed", "user_count", "role_count"]
    list_filter = ["managed", "organization"]
    search_fields = ["name"]
    filter_horizontal = ["users"]
    readonly_fields = ["created", "modified", "effective_permissions"]
    inlines = [GroupRoleAssignmentByGroupInline]

    fieldsets = [
        (None, {"fields": ["name", "organization", "managed"]}),
        ("Members", {"fields": ["users"]}),
        ("Info", {"fields": ["created", "modified"]}),
        ("Effective Permissions", {"fields": ["effective_permissions"]}),
    ]

    def user_count(self, obj):
        return obj.users.count()

    user_count.short_description = "Users"

    def role_count(self, obj):
        return obj.role_assignments.count()

    role_count.short_description = "Roles"

    def effective_permissions(self, obj):
        """Show a summary of what this group's users can access."""
        assignments = obj.role_assignments.select_related("role").prefetch_related("role__policies")
        if not assignments:
            return "No roles assigned."
        rows = []
        for assignment in assignments:
            role = assignment.role
            for p in role.policies.all():
                ref = _render_object_link(p.resource, p.field_name, p.constant_value)
                rows.append(
                    f"<tr><td>{role.name}</td><td>{p.resource}</td><td>{p.action}</td>"
                    f"<td>{p.field_name} {p.operator} {p.constant_value or '<i>user_id</i>'}</td>"
                    f"<td>{ref}</td></tr>"
                )
        if not rows:
            return "Roles assigned but no policies defined."
        table = (
            '<table style="border-collapse:collapse">'
            "<tr><th>Role</th><th>Resource</th><th>Action</th><th>Filter</th><th>Object</th></tr>"
            + "".join(rows)
            + "</table>"
        )
        return format_html(table)

    effective_permissions.short_description = "Effective Permissions"


# ---------------------------------------------------------------------------
# GroupRoleAssignment admin
# ---------------------------------------------------------------------------


@admin.register(GroupRoleAssignment)
class GroupRoleAssignmentAdmin(admin.ModelAdmin):
    list_display = ["id", "group_link", "role_link", "created"]
    list_filter = ["group", "role"]
    autocomplete_fields = ["group", "role"]
    readonly_fields = ["created", "modified"]

    def group_link(self, obj):
        url = reverse("admin:dab_opa_opagroup_change", args=[obj.group_id])
        return format_html('<a href="{}">{}</a>', url, obj.group.name)

    group_link.short_description = "Group"
    group_link.admin_order_field = "group__name"

    def role_link(self, obj):
        url = reverse("admin:dab_opa_role_change", args=[obj.role_id])
        return format_html('<a href="{}">{}</a>', url, obj.role.name)

    role_link.short_description = "Role"
    role_link.admin_order_field = "role__name"


# ---------------------------------------------------------------------------
# Custom admin views for AJAX lookups
# ---------------------------------------------------------------------------


class OPAAdminSite:
    """Register custom admin URLs for OPA-specific AJAX endpoints."""

    @staticmethod
    def get_urls():
        return [
            path(
                "dab_opa/api/registry/",
                admin.site.admin_view(registry_api),
                name="opa-registry-api",
            ),
            path(
                "dab_opa/api/object_lookup/",
                admin.site.admin_view(object_lookup_api),
                name="opa-object-lookup",
            ),
        ]


def registry_api(request):
    """Return the OPA registry data for use by admin JS.

    GET /admin/dab_opa/api/registry/
    Returns: {resources: {name: {actions: [...], fields: [...]}}}
    """
    data = {}
    for name, resource_def in opa_registry.resources.items():
        fields = list(opa_registry.get_fields(name).keys())
        data[name] = {
            "actions": resource_def["actions"],
            "fields": fields,
        }
    return JsonResponse({"resources": data})


def object_lookup_api(request):
    """Return objects for a given resource and field, for the constant_value picker.

    GET /admin/dab_opa/api/object_lookup/?resource=inventory&field=organization_id
    Returns: {objects: [{id: 1, label: "Org Name"}, ...]}
    """
    resource = request.GET.get("resource", "")
    field = request.GET.get("field", "")
    search = request.GET.get("q", "")

    if not resource or not field:
        return JsonResponse({"objects": []})

    try:
        field_def = opa_registry.get_field(resource, field)
    except ValueError:
        return JsonResponse({"objects": []})

    # Determine which model to query based on the field type
    django_path = field_def["django_path"]
    field_type = field_def.get("type", "")

    if field_type == "pk" and field == "id":
        # The field IS the resource model's PK — list objects of this resource
        model_cls = opa_registry.get_model(resource)
    elif field_type == "fk":
        # FK field — resolve the related model
        resource_model = opa_registry.get_model(resource)
        try:
            django_field = resource_model._meta.get_field(django_path)
            model_cls = django_field.related_model
        except Exception:
            return JsonResponse({"objects": []})
    else:
        return JsonResponse({"objects": []})

    # Query the model
    qs = model_cls.objects.all()
    if search:
        # Try to filter by name
        if hasattr(model_cls, "name"):
            qs = qs.filter(name__icontains=search)
        elif hasattr(model_cls, "username"):
            qs = qs.filter(username__icontains=search)

    objects = []
    for obj in qs[:50]:
        label = str(obj)
        if hasattr(obj, "name"):
            label = obj.name
        elif hasattr(obj, "username"):
            label = obj.username
        objects.append({"id": obj.pk, "label": f"{label} (pk={obj.pk})"})

    return JsonResponse({"objects": objects})


# Hook the custom URLs into the admin
_original_get_urls = admin.AdminSite.get_urls


def _patched_get_urls(self):
    return OPAAdminSite.get_urls() + _original_get_urls(self)


admin.AdminSite.get_urls = _patched_get_urls


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _render_object_link(resource, field_name, constant_value):
    """Render an admin link to the referenced object, if possible."""
    if not constant_value:
        return "-"

    try:
        field_def = opa_registry.get_field(resource, field_name)
    except ValueError:
        return "-"

    field_type = field_def.get("type", "")
    django_path = field_def["django_path"]

    try:
        if field_type == "pk" and field_name == "id":
            model_cls = opa_registry.get_model(resource)
        elif field_type == "fk":
            resource_model = opa_registry.get_model(resource)
            django_field = resource_model._meta.get_field(django_path)
            model_cls = django_field.related_model
        else:
            return str(constant_value)
    except Exception:
        return str(constant_value)

    try:
        obj = model_cls.objects.get(pk=constant_value)
        app_label = model_cls._meta.app_label
        model_name = model_cls._meta.model_name
        try:
            url = reverse(f"admin:{app_label}_{model_name}_change", args=[obj.pk])
            label = getattr(obj, "name", None) or str(obj)
            return format_html('<a href="{}">{}</a>', url, label)
        except Exception:
            label = getattr(obj, "name", None) or str(obj)
            return label
    except Exception:
        return f"{constant_value} (not found)"
