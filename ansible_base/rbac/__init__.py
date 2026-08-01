from ansible_base.rbac.permission_registry import permission_registry

__all__ = [
    'bulk_give_permissions',
    'bulk_remove_permissions',
    'permission_registry',
]


def __getattr__(name):
    if name in ('bulk_give_permissions', 'bulk_remove_permissions'):
        from ansible_base.rbac.pipeline import bulk_give_permissions, bulk_remove_permissions

        return bulk_give_permissions if name == 'bulk_give_permissions' else bulk_remove_permissions
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
