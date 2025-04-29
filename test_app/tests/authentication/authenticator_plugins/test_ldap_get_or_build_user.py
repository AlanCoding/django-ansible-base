import importlib
from unittest import mock
from unittest.mock import MagicMock

import pytest

from ansible_base.authentication.authenticator_plugins import ldap


@pytest.mark.django_db
@pytest.mark.parametrize(
    "username",
    [
        ("Timmy"),
        ("TIMMY"),
        ("TiMmY"),
    ],
)
def test_get_or_build_user(username, ldap_authenticator):
    with mock.patch(
        'ansible_base.authentication.utils.authentication.get_or_create_authenticator_user', return_value=(None, None, None)
    ) as get_or_create_authenticator_user:
        importlib.reload(ldap)
        plugin = ldap.AuthenticatorPlugin(database_instance=ldap_authenticator)
        ldap_object = MagicMock()
        plugin.get_or_build_user(username, ldap_object)
        assert get_or_create_authenticator_user.called
        assert username.lower() in get_or_create_authenticator_user.call_args[0]
        assert username not in get_or_create_authenticator_user.call_args[0]
