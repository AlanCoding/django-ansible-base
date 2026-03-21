from ansible_base.lib.routers import AssociationResourceRouter
from ansible_base.opa.api import views

router = AssociationResourceRouter()

router.register(r"opa_roles", views.RoleViewSet, basename="oparole")
router.register(r"opa_policies", views.PolicyViewSet, basename="opapolicy")
router.register(
    r"opa_groups",
    views.OPAGroupViewSet,
    basename="opagroup",
)
router.register(
    r"opa_group_role_assignments",
    views.GroupRoleAssignmentViewSet,
    basename="opagrouproleassignment",
)
