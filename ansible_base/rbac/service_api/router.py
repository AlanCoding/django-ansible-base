from ansible_base.lib.routers import AssociationResourceRouter

from . import views

service_router = AssociationResourceRouter()

service_router.register(r'role-types', views.RoleContentTypeViewSet)
service_router.register(r'role-permissions', views.RolePermissionTypeViewSet)
