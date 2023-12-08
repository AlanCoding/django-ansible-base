from rest_framework.serializers import ModelSerializer

from ansible_base.lib.serializers.common import NamedCommonModelSerializer
from test_app.models import EncryptionModel, Organization, User


class EncryptionModelSerializer(NamedCommonModelSerializer):
    reverse_url_name = 'encryptiontest-detail'

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
