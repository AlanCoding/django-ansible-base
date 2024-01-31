from rest_framework.routers import SimpleRouter

from ansible_base.rbac.api import views

router = SimpleRouter()

router.register(r'role_definitions', views.RoleDefinitionViewSet, basename='role_definition')
router.register(r'role_user_assignments', views.UserAssignmentViewSet, basename='userassignment')
router.register(r'role_team_assignments', views.TeamAssignmentViewSet, basename='teamassignment')
