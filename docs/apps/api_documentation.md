# Open API and Swagger documentation

django-ansible-base uses django-spectacular to auto-generate both Open API and Swagger documentation of the API.

## Settings

Add `ansible_base.api_documentation` to your installed apps.
Plus do what we tell you here.

```
from ansible_base.lib.dynamic_config.constants import api_documentation


INSTALLED_APPS = [
    ...
    'ansible_base.api_documentation',
    'drf_spectacular',
]

REST_FRAMEWORK = {
    ...
    'SPECTACULAR_SETTINGS': api_documentation.dab_spectacular_settings,
    'DEFAULT_SCHEMA_CLASS': api_documentation.auto_schema,
    ...
}
```

If you do not set these, our validators will let you know by throwing an error.
See [dynamic_settings](../Installation.md) for more information.


## URLS

This feature includes URLs which you will get if you are using [dynamic urls](../..//Installation.md)

If you want to manually add the urls without dynamic urls add the following to your urls.py:
```
from ansible_base.api_documentation import urls

urlpatterns = [
    ...
    path('api/v1/', include(base_auth_urls.api_version_urls)),
    ...
]
```
