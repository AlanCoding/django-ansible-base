from django.urls import path

from ansible_base.opa.api.router import router
from ansible_base.opa.api.views import UserEffectiveScopeView

api_version_urls = router.urls + [
    path("opa/effective_scope/", UserEffectiveScopeView.as_view(), name="opa-effective-scope"),
]
