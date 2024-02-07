from rest_framework.routers import SimpleRouter

from ansible_base.rbac.api import views

router = SimpleRouter()

router.register(r'role_definitions', views.RoleDefinitionViewSet, basename='roledefinition')
router.register(r'role_user_assignments', views.RoleUserAssignmentViewSet, basename='roleuserassignment')
router.register(r'role_team_assignments', views.RoleTeamAssignmentViewSet, basename='roleteamassignment')
