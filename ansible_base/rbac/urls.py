from django.urls import include, path

from ansible_base.rbac.api.router import router
from ansible_base.rbac.apps import AnsibleRBACConfig
from ansible_base.rbac.data_api.router import data_router
from ansible_base.rbac.data_api.views import RoleDataIndexView, RoleMetadataView


class OldRoleMetadataView(RoleMetadataView):
    deprecated = True


app_name = AnsibleRBACConfig.label

api_version_urls = [
    path('', include(router.urls)),
    path(r'role_data/', RoleDataIndexView.as_view(), name='role-data-index'),
    path(r'role_data/', include(data_router.urls)),
    path(r'role_data/allowed_permissions/', RoleMetadataView.as_view(), name='role-allowed-permissions'),
    path(r'role_metadata/', OldRoleMetadataView.as_view(), name="role-metadata"),  # deprecated
]

root_urls = []

api_urls = []
