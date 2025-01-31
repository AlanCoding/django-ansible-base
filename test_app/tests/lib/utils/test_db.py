import threading
import time

import psycopg
import pytest
from django.conf import settings
from django.db import connection
from django.db.utils import OperationalError
from django.test import override_settings

from ansible_base.lib.utils.db import (
    advisory_lock,
    get_pg_notify_params,
    migrations_are_complete,
    psycopg_conn_string_from_settings_dict,
    psycopg_kwargs_from_settings_dict,
)


@pytest.mark.django_db
def test_migrations_are_complete():
    "If you are running tests, migrations (test database) should be complete"
    assert migrations_are_complete()


class TestPGNotifyConnection:
    TEST_DATABASE_DICT = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "HOST": "https://foo.invalid",
            "PORT": 55434,
            "USER": "dab_user",
            "PASSWORD": "dabbing",
            "NAME": "dab_db",
        }
    }
    PSYCOPG_KWARGS = {
        'dbname': 'dab_db',
        'client_encoding': 'UTF8',
        # kwargs containing objects can not be compared so they will be ignored
        # 'cursor_factory': <class 'django.db.backends.postgresql.base.Cursor'>,
        'user': 'dab_user',
        'password': 'dabbing',
        'host': 'https://foo.invalid',
        'port': 55434,
        # 'context': <psycopg.adapt.AdaptersMap object at 0x7f537f2d9f70>,
        'prepare_threshold': None,
        'autocommit': True,
    }

    @pytest.fixture
    def mock_settings(self):
        with override_settings(DATABASES=self.TEST_DATABASE_DICT, USE_TZ=False):
            yield

    def _trim_python_objects(self, psycopg_params):
        # These remove those commented-out kwargs in PSYCOPG_KWARGS
        psycopg_params.pop('cursor_factory')
        psycopg_params.pop('context')
        return psycopg_params

    def test_default_behavior(self, mock_settings):
        params = self._trim_python_objects(get_pg_notify_params())
        assert params == self.PSYCOPG_KWARGS

    def test_pg_notify_extra_options(self, mock_settings):
        params = self._trim_python_objects(get_pg_notify_params(application_name='joe_connection'))
        expected = self.PSYCOPG_KWARGS.copy()
        expected['application_name'] = 'joe_connection'
        assert params == expected

    def test_lister_databases(self, mock_settings):
        LISTENER_DATABASES = {"default": {"HOST": "https://foo.anotherhost.invalid"}}
        with override_settings(LISTENER_DATABASES=LISTENER_DATABASES):
            params = self._trim_python_objects(get_pg_notify_params())
            assert params['host'] == "https://foo.anotherhost.invalid"

    def test_pg_notify_databases(self, mock_settings):
        PG_NOTIFY_DATABASES = {"default": {"HOST": "https://foo.anotherhost2.invalid"}}
        with override_settings(PG_NOTIFY_DATABASES=PG_NOTIFY_DATABASES):
            params = self._trim_python_objects(get_pg_notify_params())
            assert params['host'] == "https://foo.anotherhost2.invalid"

    def test_psycopg_kwargs_from_settings_dict(self):
        "More of a unit test, doing the same thing"
        test_dict = self.TEST_DATABASE_DICT["default"].copy()
        test_dict['OPTIONS'] = {'autocommit': True}
        with override_settings(USE_TZ=False):
            psycopg_params = self._trim_python_objects(psycopg_kwargs_from_settings_dict(test_dict))
            assert psycopg_params == self.PSYCOPG_KWARGS

    def test_psycopg_kwargs_use(self):
        "This assures that the data we get for the kwargs are usable, and demos how to use"
        if connection.vendor == 'sqlite':
            pytest.skip('Test needs to connect to postgres which is not running')

        test_dict = settings.DATABASES['default'].copy()
        test_dict['OPTIONS'] = {'autocommit': True}
        with override_settings(USE_TZ=False):
            psycopg_params = self._trim_python_objects(psycopg_kwargs_from_settings_dict(test_dict))

        psycopg.connect(**psycopg_params)

    def test_listener_string_production(self):
        "This is a test to correspond to PG_NOTIFY_DSN_SERVER type settings in eda-server"
        with override_settings(USE_TZ=False):
            args = psycopg_conn_string_from_settings_dict(
                {
                    "ENGINE": "django.db.backends.postgresql",
                    "HOST": "127.0.0.1",
                    "PORT": 5432,
                    "USER": "postgres",
                    "PASSWORD": "DB_PASSWORD",
                    "NAME": "eda",
                    "OPTIONS": {
                        "sslmode": "allow",
                        "sslcert": "",
                        "sslkey": "",
                        "sslrootcert": "",
                    },
                }
            )
        assert args == (
            "dbname=eda sslmode=allow sslcert='' sslkey='' sslrootcert='' client_encoding=UTF8 user=postgres password=DB_PASSWORD host=127.0.0.1 port=5432"
        )

    def test_listener_string_production_use(self):
        "This assures that the data we get for the connection string is usable, and demos how to use"
        if connection.vendor == 'sqlite':
            pytest.skip('Test needs to connect to postgres which is not running')
        args = psycopg_conn_string_from_settings_dict(settings.DATABASES['default'])
        psycopg.connect(conninfo=args)


class TestAdvisoryLock:
    @pytest.fixture(autouse=True)
    def skip_if_sqlite(self):
        if connection.vendor == 'sqlite':
            pytest.skip('Advisory lock is not written for sqlite')

    @pytest.mark.django_db
    def test_get_unclaimed_lock(self):
        with advisory_lock('test_get_unclaimed_lock'):
            pass

    @staticmethod
    def background_task(django_db_blocker):
        # HACK: as a thread the pytest.mark.django_db will not work
        django_db_blocker.unblock()
        with advisory_lock('background_task_lock'):
            time.sleep(0.1)

    @pytest.mark.django_db
    def test_determine_lock_is_held(self, django_db_blocker):
        thread = threading.Thread(target=TestAdvisoryLock.background_task, args=(django_db_blocker,))
        thread.start()
        for _ in range(20):
            with advisory_lock('background_task_lock', wait=False) as held:
                if held is False:
                    break
            time.sleep(0.01)
        else:
            raise RuntimeError('Other thread never obtained lock')
        thread.join()

    @pytest.mark.django_db
    def test_tuple_lock(self):
        with advisory_lock([1234, 4321]):
            pass

    @pytest.mark.django_db
    def test_invalid_tuple_name(self):
        with pytest.raises(ValueError):
            with advisory_lock(['test_invalid_tuple_name', 'foo']):
                pass

    @pytest.mark.django_db
    def test_lock_session_timeout_milliseconds(self):
        with pytest.raises(OperationalError) as exc:
            # uses miliseconds units
            with advisory_lock('test_lock_session_timeout_milliseconds', lock_session_timeout_milliseconds=2):
                time.sleep(3)
        assert 'the connection is lost' in str(exc)
