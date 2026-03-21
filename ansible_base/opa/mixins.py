import logging

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
