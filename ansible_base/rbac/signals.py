from django.dispatch import Signal

# Sent after give_assignments creates assignments.
# kwargs: assignment_data (list[tuple[AssignmentBase, ContentObject | None]])
# Each tuple pairs an assignment with its content object.
#
# Content objects are populated when called from bulk_give_permissions (which has the model instances).
# Content objects are None when give_assignments is called directly without content_objects parameter.
# Consumers can choose to fetch content objects if needed (e.g., via bulk GFK query).
dab_rbac_assignments_created = Signal()

# Sent before remove_assignments deletes assignments.
# kwargs: assignment_data (list[tuple[AssignmentBase, ContentObject | None]])
# Each tuple pairs an assignment with its content object.
#
# Content objects are populated when called from bulk_remove_permissions (which has the model instances).
# Content objects are None when remove_assignments is called directly without content_objects parameter.
# Consumers can choose to fetch content objects if needed (e.g., via bulk GFK query).
dab_rbac_assignments_pre_delete = Signal()
