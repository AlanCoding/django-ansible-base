from django.dispatch import Signal

# Sent after bulk_give_permissions creates assignments.
# kwargs: assignment_data (list[tuple[AssignmentBase, ContentObject | None]])
# Each tuple pairs an assignment with its content object (or None if unavailable)
dab_rbac_assignments_created = Signal()

# Sent before bulk_remove_permissions deletes assignments.
# kwargs: assignment_data (list[tuple[AssignmentBase, ContentObject | None]])
# Each tuple pairs an assignment with its content object (or None if unavailable)
dab_rbac_assignments_pre_delete = Signal()
