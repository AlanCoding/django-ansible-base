# Import fixtures from parent directories by importing the specific fixtures we need
from test_app.tests.rbac.conftest import global_inv_rd, inv_rd, rando
from test_app.tests.rbac.remote.conftest import foo_permission, foo_rd, foo_type

__all__ = ['rando', 'inv_rd', 'global_inv_rd', 'foo_type', 'foo_rd', 'foo_permission']
