from django.contrib import admin

from ansible_base.opa.models import GroupRoleAssignment, OPAGroup, Policy, Role


class PolicyInline(admin.TabularInline):
    model = Policy
    extra = 0


@admin.register(OPAGroup)
class OPAGroupAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "managed")
    list_filter = ("managed",)
    filter_horizontal = ("users",)


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ("name", "managed")
    list_filter = ("managed",)
    inlines = [PolicyInline]


@admin.register(Policy)
class PolicyAdmin(admin.ModelAdmin):
    list_display = ("role", "resource", "action", "field_name", "operator", "value_type", "constant_value")
    list_filter = ("resource", "action", "value_type")


@admin.register(GroupRoleAssignment)
class GroupRoleAssignmentAdmin(admin.ModelAdmin):
    list_display = ("group", "role")
