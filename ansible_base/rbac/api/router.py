from ansible_base.lib.routers import AssociationResourceRouter

from ansible_base.rbac.api import views

router = AssociationResourceRouter()

router.register(r'role_definitions', views.RoleDefinitionViewSet, basename='roledefinition')
router.register(r'role_user_assignments', views.RoleUserAssignmentViewSet, basename='roleuserassignment')
router.register(r'role_team_assignments', views.RoleTeamAssignmentViewSet, basename='roleteamassignment')
