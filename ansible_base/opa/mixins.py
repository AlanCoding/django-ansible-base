import logging

from django.conf import settings
from django.db.models import ForeignKey
from django.forms import model_to_dict
from rest_framework.exceptions import PermissionDenied

from ansible_base.lib.utils.db import ensure_transaction
from ansible_base.opa.queryset import filter_queryset_for_user
from ansible_base.opa.registry import opa_registry

logger = logging.getLogger(__name__)


class OPAQuerySetMixin:
    """View mixin that filters querysets through OPA.

    Apply to DRF viewsets to restrict list results to objects the
    requesting user is authorized to read. Works with OPAPermission
    for object-level checks.
    """

    def filter_queryset(self, qs):
        model_cls = qs.model
        try:
            opa_registry.get_resource_name_for_model(model_cls)
        except ValueError:
            return super().filter_queryset(qs)

        qs = filter_queryset_for_user(qs, self.request.user, "read")
        return super().filter_queryset(qs)


def _get_parent_field_name(model_cls):
    """Get the parent FK field name for a model from the OPA resource config."""
    try:
        resource_name = opa_registry.get_resource_name_for_model(model_cls)
    except ValueError:
        return None
    resource_def = opa_registry.get_resource(resource_name)
    return resource_def.get("parent_field_name")


def _opa_required_related_action(field):
    """Determine the OPA action required for changing a FK field.

    Parent FK (e.g., organization) -> 'add' on the child resource
    Non-parent FK (e.g., credential) -> first matching action from
        ANSIBLE_BASE_CHECK_RELATED_PERMISSIONS on the related resource
    """
    parent_field_name = _get_parent_field_name(field.model)
    if field.name == parent_field_name:
        return "add", opa_registry.get_resource_name_for_model(field.model)

    rel_cls = field.related_model
    try:
        rel_resource = opa_registry.get_resource_name_for_model(rel_cls)
    except ValueError:
        return None, None

    rel_actions = set(opa_registry.get_actions(rel_resource))
    custom_perms = dict(rel_cls._meta.permissions)
    for action in getattr(settings, "ANSIBLE_BASE_CHECK_RELATED_PERMISSIONS", ["use", "change", "view"]):
        codename = f"{action}_{rel_cls._meta.model_name}"
        if action in rel_cls._meta.default_permissions or codename in custom_perms:
            if action in rel_actions:
                return action, rel_resource
    return None, None


def _opa_related_permission_fields(model_cls):
    """Yield FK fields on model_cls whose related model is registered in OPA."""
    for field in model_cls._meta.concrete_fields:
        if isinstance(field, ForeignKey):
            try:
                opa_registry.get_resource_name_for_model(field.related_model)
                yield field
            except ValueError:
                continue


def _build_related_checks(model_cls, old_data, new_data):
    """Build the 'related' dict for tier 2 evaluation from changed FK fields.

    Returns:
        Dict of field_name -> {resource, action, id, org_id} for changed FKs.
    """
    related = {}
    for field in _opa_related_permission_fields(model_cls):
        old_val = old_data.get(field.name)
        new_val = new_data.get(field.name)

        if field.name in old_data and old_val == new_val:
            continue

        action, resource = _opa_required_related_action(field)
        if action is None:
            continue

        if field.null and new_val is None:
            parent_field_name = _get_parent_field_name(field.model)
            if field.name != parent_field_name:
                continue

        parent_field_name = _get_parent_field_name(field.model)
        if field.name == parent_field_name:
            related[field.name] = {
                "resource": resource,
                "action": action,
                "id": None,
                "org_id": new_val,
            }
        else:
            related[field.name] = {
                "resource": resource,
                "action": action,
                "id": new_val,
            }

    return related


def opa_check_related_permissions(user, instance, action, old_data, new_data):
    """Check related object permissions via OPA tier 2 evaluation.

    Sends a full tier 2 OPA query with both the object and its related
    entries. OPA evaluates object_allowed and related_denied together.

    Raises PermissionDenied if the user lacks permission on any changed FK field.
    """
    from ansible_base.opa.queryset import check_object_access

    if user.is_superuser:
        return

    model_cls = type(instance)
    related = _build_related_checks(model_cls, old_data, new_data)
    if not related:
        return

    resource_name = opa_registry.get_resource_name_for_model(model_cls)
    result = check_object_access(user, resource_name, action, instance, related=related)

    denied_fields = result.get("related_denied", [])
    if denied_fields:
        errors = {field: "You do not have permission to use this object." for field in denied_fields}
        logger.warning(
            "User %s lacks %s related permissions: %s",
            user.pk, model_cls._meta.model_name, list(denied_fields),
        )
        raise PermissionDenied(errors)


class OPARelatedAccessMixin:
    """Serializer mixin that checks OPA permissions on related objects.

    Drop-in replacement for RBAC's RelatedAccessMixin. Checks that the
    user has appropriate permissions on FK fields being set or changed.
    """

    def create(self, validated_data):
        view = self.context.get("view", None)
        if not view or not view.request:
            return super().create(validated_data)

        with ensure_transaction():
            instance = super().create(validated_data)
            opa_check_related_permissions(
                view.request.user,
                instance,
                "add",
                {},
                model_to_dict(instance),
            )
        return instance

    def update(self, instance, validated_data):
        view = self.context.get("view", None)
        if not view or not view.request:
            return super().update(instance, validated_data)

        old_data = model_to_dict(instance)
        with ensure_transaction():
            updated_instance = super().update(instance, validated_data)
            opa_check_related_permissions(
                view.request.user,
                updated_instance,
                "change",
                old_data,
                model_to_dict(updated_instance),
            )
        return updated_instance
