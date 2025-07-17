from django.urls import include, path

from .router import service_router

# These will be included by the resource registry
rbac_service_urls = [
    path('service-index/', include(service_router.urls)),
]
