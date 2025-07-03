from django.urls import include, path

from ansible_base.rbac.api.router import router
from ansible_base.rbac.api.views import RoleMetadataView
from ansible_base.rbac.apps import AnsibleRBACConfig

from .service_api.router import service_router

app_name = AnsibleRBACConfig.label


service_urls = [
    path('', include(service_router.urls)),
]

api_version_urls = [
    path('', include(router.urls)),
    path('service-index/', include(service_urls)),
    path(r'role_metadata/', RoleMetadataView.as_view(), name="role-metadata"),
]

root_urls = []

api_urls = []
