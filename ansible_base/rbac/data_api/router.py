from ansible_base.lib.routers import AssociationResourceRouter
from ansible_base.rbac.data_api import views

data_router = AssociationResourceRouter()

data_router.register(r'types', views.TypeViewSet, basename='rbactype')
data_router.register(r'types/(?P<model_name>[^/.]+)/objects', views.ObjectViewSet, basename='rbacobject')
data_router.register(r'types/(?P<model_name>[^/.]+)/objects/(?P<object_id>[^/.]+)/user_access', views.RoleUserAssignmentViewSet, basename='rbacuserassignment')
data_router.register(r'users', views.UserInfoViewSet, basename='rbacuser')
