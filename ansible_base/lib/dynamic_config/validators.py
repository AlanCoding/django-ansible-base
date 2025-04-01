from dynaconf import Validator

from .constants import api_documentation, rest_filters


def has_spectacular(v):
    return bool('drf_spectacular' in v)


def has_drf_spectacular_settings(v):
    if 'DEFAULT_SCHEMA_CLASS' not in v:
        return False
    if v['DEFAULT_SCHEMA_CLASS'] != api_documentation.auto_schema:
        return False

    spectacular_settings = v['SPECTACULAR_SETTINGS']
    for key, value in api_documentation.dab_spectacular_settings.items():
        user_value = spectacular_settings.get(key)
        if user_value != value:
            return False
    return True


def has_all_rest_filters(v):
    user_filters = v.get('DEFAULT_FILTER_BACKENDS', [])
    for cls_name in rest_filters.dab_rest_filters:
        if cls_name not in user_filters:
            return False
    return True


def has_social_django(v):
    return bool('social_django' in v)


dab_validators = {
    "ansible_base.api_documentation": [
        Validator("INSTALLED_APPS", condition=has_spectacular),
        Validator("REST_FRAMEWORK", condition=has_drf_spectacular_settings),
    ],
    "ansible_base.rest_filters": [
        Validator(
            "REST_FRAMEWORK",
            condition=has_all_rest_filters,
            messages={
                "condition": "{name} lacks required rest_filters entries in DEFAULT_FILTER_BACKENDS value=({value}) in env {env}, required: "
                + str(rest_filters.dab_rest_filters)
            },
        )
    ],
    "ansible_base.authentication": [Validator("INSTALLED_APPS", condition=has_social_django)],
}
