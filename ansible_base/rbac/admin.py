from django.contrib import admin

from ansible_base.rbac.models import ObjectRole, RoleDefinition, RoleEvaluation, TeamAssignment, UserAssignment


class ReadOnlyAdmin(admin.ModelAdmin):
    """For cached data by the RBAC system, not editable"""

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


admin.site.register(RoleDefinition)
# TODO: assignments will still not be functional in the admin pages without custom logic
admin.site.register(UserAssignment)
admin.site.register(TeamAssignment)
admin.site.register(ObjectRole, ReadOnlyAdmin)
admin.site.register(RoleEvaluation, ReadOnlyAdmin)
