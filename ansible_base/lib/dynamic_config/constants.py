from types import SimpleNamespace

rest_filters = SimpleNamespace(
    reserved_names=(
        'page',
        'page_size',
        'format',
        'order',
        'order_by',
        'search',
        'type',
        'host_filter',
        'count_disabled',
        'no_truncate',
        'limit',
        'validate',
    ),
    dab_rest_filters=(
        'ansible_base.rest_filters.rest_framework.type_filter_backend.TypeFilterBackend',
        'ansible_base.rest_filters.rest_framework.field_lookup_backend.FieldLookupBackend',
        'rest_framework.filters.SearchFilter',
        'ansible_base.rest_filters.rest_framework.order_backend.OrderByBackend',
    ),
)


api_documentation = SimpleNamespace(
    auto_schema='drf_spectacular.openapi.AutoSchema',
    dab_spectacular_settings={
        'TITLE': 'Open API',
        'DESCRIPTION': 'Open API',
        'VERSION': 'v1',
        'SCHEMA_PATH_PREFIX': '/api/v1/',
        'COMPONENT_NO_READ_ONLY_REQUIRED': True,
    },
)
