from rest_framework import permissions
from rest_framework.routers import SimpleRouter
from rest_framework.viewsets import ModelViewSet

from ansible_base.rbac.api.permissions import AnsibleBaseObjectPermissions
from test_app.models import EncryptionModel, Organization, User
from test_app.serializers import EncryptionModelSerializer, OrganizationSerializer, UserSerializer


class UserViewSet(ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]


class OrganizationViewSet(ModelViewSet):
    serializer_class = OrganizationSerializer
    permission_classes = [AnsibleBaseObjectPermissions]

    def get_queryset(self):
        return Organization.accessible_objects(self.request.user, 'view')


class EncryptedModelViewSet(ModelViewSet):
    serializer_class = EncryptionModelSerializer
    permission_classes = [AnsibleBaseObjectPermissions]

    def get_queryset(self):
        return EncryptionModel.accessible_objects(self.request.user, 'view')


router = SimpleRouter()

router.register(r'users', UserViewSet)
router.register(r'organizations', OrganizationViewSet, basename='organization')
router.register(r'encryption_model', EncryptedModelViewSet, basename='encryptedmodel')
