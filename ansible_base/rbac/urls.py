from django.urls import include, path

from ansible_base.rbac.api.router import router
from ansible_base.rbac.api.views import RoleMetadataView, TeamAccessAssignmentViewSet, TeamAccessViewSet, UserAccessAssignmentViewSet, UserAccessViewSet
from ansible_base.rbac.apps import AnsibleRBACConfig

app_name = AnsibleRBACConfig.label

user_access_view = UserAccessViewSet.as_view({'get': 'list'})
team_access_view = TeamAccessViewSet.as_view({'get': 'list'})
user_access_assignment_view = UserAccessAssignmentViewSet.as_view({'get': 'list'})
team_access_assignment_view = TeamAccessAssignmentViewSet.as_view({'get': 'list'})

api_version_urls = [
    path('', include(router.urls)),
    path(r'role_metadata/', RoleMetadataView.as_view(), name="role-metadata"),
    path('role_user_access/<str:model_name>/<int:pk>/', user_access_view, name="role-user-access"),
    path('role_team_access/<str:model_name>/<int:pk>/', team_access_view, name="role-team-access"),
    path(
        'role_user_access/<str:model_name>/<int:pk>/<str:actor_pk>/',
        user_access_assignment_view,
        name='role-user-access-assignments',
    ),
    path(
        'role_team_access/<str:model_name>/<int:pk>/<str:actor_pk>/',
        team_access_assignment_view,
        name='role-team-access-assignments',
    ),
]

root_urls = []

api_urls = []
