from rest_framework.serializers import ModelSerializer

from ansible_base.lib.serializers.common import NamedCommonModelSerializer
from test_app.models import EncryptionModel, Inventory, Organization, User, Cow, UUIDModel


class EncryptionModelSerializer(NamedCommonModelSerializer):
    reverse_url_name = 'encryptedmodel-detail'

    class Meta:
        model = EncryptionModel
        fields = NamedCommonModelSerializer.Meta.fields + [x.name for x in EncryptionModel._meta.concrete_fields]


class OrganizationSerializer(NamedCommonModelSerializer):
    reverse_url_name = 'organization-detail'

    class Meta:
        model = Organization
        fields = '__all__'


class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'


class InventorySerializer(ModelSerializer):
    class Meta:
        model = Inventory
        fields = '__all__'


class CowSerializer(ModelSerializer):
    class Meta:
        model = Cow
        fields = '__all__'


class UUIDModelSerializer(ModelSerializer):
    class Meta:
        model = UUIDModel
        fields = '__all__'
