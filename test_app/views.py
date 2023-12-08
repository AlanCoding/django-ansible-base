from rest_framework import permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.routers import SimpleRouter
from rest_framework.viewsets import ModelViewSet

from ansible_base.rbac.api.permissions import AnsibleBaseObjectPermissions
from test_app.models import User
from test_app.serializers import CowSerializer, EncryptionModelSerializer, InventorySerializer, OrganizationSerializer, UserSerializer, UUIDModelSerializer


class UserViewSet(ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]


class TestAppViewSet(ModelViewSet):
    permission_classes = [AnsibleBaseObjectPermissions]

    def get_queryset(self):
        return self.serializer_class.Meta.model.access_qs(self.request.user)


class OrganizationViewSet(TestAppViewSet):
    serializer_class = OrganizationSerializer


class EncryptedModelViewSet(TestAppViewSet):
    serializer_class = EncryptionModelSerializer


class InventoryViewSet(TestAppViewSet):
    serializer_class = InventorySerializer


class CowViewSet(TestAppViewSet):
    serializer_class = CowSerializer

    @action(detail=True, methods=['post'])
    def cowsay(self, request, pk=None):
        return Response({'detail': 'moooooo'})


class UUIDModelViewSet(TestAppViewSet):
    serializer_class = UUIDModelSerializer


router = SimpleRouter()

router.register(r'users', UserViewSet)
router.register(r'organizations', OrganizationViewSet, basename='organization')
router.register(r'encryption_models', EncryptedModelViewSet, basename='encryptedmodel')
router.register(r'inventories', InventoryViewSet, basename='inventory')
router.register(r'cows', CowViewSet, basename='cow')
router.register(r'uuidmodels', UUIDModelViewSet, basename='uuidmodel')
