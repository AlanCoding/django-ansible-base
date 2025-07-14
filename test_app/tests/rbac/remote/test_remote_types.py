import uuid

import pytest

from ansible_base.rbac.remote import RemoteObject


@pytest.mark.django_db
def test_validate_object_id_uuid(foo_type_uuid):
    "The 42 primary key is invalid for uuid type objects"
    with pytest.raises(ValueError):
        RemoteObject(content_type=foo_type_uuid, object_id=42)


@pytest.mark.django_db
def test_validate_object_id_int(foo_type):
    with pytest.raises(ValueError):
        RemoteObject(content_type=foo_type, object_id=str(uuid.uuid4()))
