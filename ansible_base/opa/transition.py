"""Dual-evaluation transition validation.

When DAB_OPA_TRANSITION_VALIDATION is True, compares OPA results with
RBAC results on every queryset filter and object access check.
Discrepancies are logged at ERROR level for investigation.

OPA is always the authoritative result — RBAC is only consulted for comparison.
"""

import logging

from ansible_base.opa.registry import opa_registry

logger = logging.getLogger("ansible_base.opa.transition")

# OPA action -> RBAC codename prefix
_ACTION_TO_CODENAME_PREFIX = {
    "read": "view",
    "change": "change",
    "delete": "delete",
    "add": "add",
}


def _is_enabled():
    return opa_registry.transition_validation


def _rbac_registered(model_cls):
    """Check if a model is registered in the RBAC permission registry."""
    try:
        from ansible_base.rbac import permission_registry

        return permission_registry.is_registered(model_cls)
    except Exception:
        return False


def _codename_for_action(model_cls, action):
    """Map OPA action to RBAC codename."""
    prefix = _ACTION_TO_CODENAME_PREFIX.get(action)
    if prefix is None:
        return None
    return f"{prefix}_{model_cls._meta.model_name}"


def validate_queryset_filter(opa_queryset, user, action):
    """Compare OPA-filtered queryset with RBAC-filtered queryset.

    Called after OPA filtering. Logs any discrepancies.
    Always returns the OPA queryset (OPA is authoritative).
    """
    if not _is_enabled():
        return opa_queryset

    model_cls = opa_queryset.model
    if not _rbac_registered(model_cls):
        return opa_queryset

    codename = _codename_for_action(model_cls, action)
    if codename is None:
        return opa_queryset

    try:
        rbac_qs = model_cls.access_qs(user, codename)
        opa_pks = set(opa_queryset.values_list("pk", flat=True))
        rbac_pks = set(rbac_qs.values_list("pk", flat=True))

        if opa_pks != rbac_pks:
            only_opa = opa_pks - rbac_pks
            only_rbac = rbac_pks - opa_pks
            logger.error(
                "TRANSITION MISMATCH queryset user=%s resource=%s action=%s "
                "opa_count=%d rbac_count=%d opa_only=%s rbac_only=%s",
                user.username if hasattr(user, "username") else user.pk,
                model_cls._meta.model_name,
                action,
                len(opa_pks),
                len(rbac_pks),
                only_opa or "{}",
                only_rbac or "{}",
            )
        else:
            logger.debug(
                "TRANSITION MATCH queryset user=%s resource=%s action=%s count=%d",
                user.username if hasattr(user, "username") else user.pk,
                model_cls._meta.model_name,
                action,
                len(opa_pks),
            )
    except Exception:
        logger.exception(
            "TRANSITION ERROR comparing queryset for user=%s resource=%s action=%s",
            user.pk,
            model_cls._meta.model_name,
            action,
        )

    return opa_queryset


def validate_object_access(opa_result, user, obj, action):
    """Compare OPA object access with RBAC object access.

    Called after OPA check. Logs any discrepancies.
    Always returns the OPA result (OPA is authoritative).
    """
    if not _is_enabled():
        return opa_result

    model_cls = type(obj)
    if not _rbac_registered(model_cls):
        return opa_result

    codename = _codename_for_action(model_cls, action)
    if codename is None:
        return opa_result

    try:
        from ansible_base.rbac.evaluations import bound_has_obj_perm

        rbac_result = bound_has_obj_perm(user, obj, codename)

        if opa_result != rbac_result:
            logger.error(
                "TRANSITION MISMATCH object user=%s resource=%s pk=%s action=%s "
                "opa=%s rbac=%s",
                user.username if hasattr(user, "username") else user.pk,
                model_cls._meta.model_name,
                obj.pk,
                action,
                opa_result,
                rbac_result,
            )
        else:
            logger.debug(
                "TRANSITION MATCH object user=%s resource=%s pk=%s action=%s result=%s",
                user.username if hasattr(user, "username") else user.pk,
                model_cls._meta.model_name,
                obj.pk,
                action,
                opa_result,
            )
    except Exception:
        logger.exception(
            "TRANSITION ERROR comparing object access for user=%s resource=%s pk=%s action=%s",
            user.pk,
            model_cls._meta.model_name,
            obj.pk,
            action,
        )

    return opa_result
