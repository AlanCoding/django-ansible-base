from ansible_base.rbac.permission_registry import permission_registry

__all__ = [
    'permission_registry',
    'bulk_rbac_caching',
]


def __getattr__(name):
    if name == 'bulk_rbac_caching':
        from ansible_base.rbac.triggers import bulk_rbac_caching

        return bulk_rbac_caching
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
