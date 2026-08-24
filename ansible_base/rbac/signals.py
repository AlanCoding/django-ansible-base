from django.dispatch import Signal

# Sent after give_assignments creates assignments.
# kwargs:
#   - assignments: list[AssignmentBase] - newly created RoleUserAssignment/RoleTeamAssignment instances
#   - content_objects: dict[tuple[int, str], ContentObject] - optional lookup by (content_type_id, object_id)
#
# Content objects dict is populated when called from bulk_give_permissions (which has the model instances).
# Content objects dict is empty when give_assignments is called directly without content_objects parameter.
# Consumers can look up content objects as: content_objects.get((assignment.content_type_id, assignment.object_id))
# Missing key means not provided; assignment.object_id is None means system role with null content object.
dab_rbac_assignments_created = Signal()

# Sent before remove_assignments deletes assignments.
# kwargs:
#   - assignments: list[AssignmentBase] - RoleUserAssignment/RoleTeamAssignment instances about to be deleted
#   - content_objects: dict[tuple[int, str], ContentObject] - optional lookup by (content_type_id, object_id)
#
# Content objects dict is populated when called from bulk_remove_permissions (which has the model instances).
# Content objects dict is empty when remove_assignments is called directly without content_objects parameter.
# Consumers can look up content objects as: content_objects.get((assignment.content_type_id, assignment.object_id))
# Missing key means not provided; assignment.object_id is None means system role with null content object.
dab_rbac_assignments_pre_delete = Signal()
