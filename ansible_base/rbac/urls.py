from django.urls import include, path

from ansible_base.rbac.api.router import router
from ansible_base.rbac.api.views import RoleMetadataView, TeamAccessViewSet, UserAccessViewSet
from ansible_base.rbac.apps import AnsibleRBACConfig

from .service_api.router import service_router

app_name = AnsibleRBACConfig.label


service_urls = [
    path('', include(service_router.urls)),
]

user_access_view = UserAccessViewSet.as_view({'get': 'list'})
team_access_view = TeamAccessViewSet.as_view({'get': 'list'})

api_version_urls = [
    path('', include(router.urls)),
    path('service-index/', include(service_urls)),
    path(r'role_metadata/', RoleMetadataView.as_view(), name="role-metadata"),
    path('role_user_access/<str:model_name>/<int:pk>/', user_access_view, name="role-user-access"),
    path('role_team_access/<str:model_name>/<int:pk>/', team_access_view, name="role-team-access"),
]

root_urls = []

api_urls = []
