from ansible_base.lib.utils import requests as dab_requests

# Global variable to hold the Django template library
register = None


def is_proxied_request():
    return dab_requests.is_proxied_request()


# Auto-register when imported in Django context
try:
    from django import template
    register = template.Library()
    register.simple_tag(is_proxied_request)
except ImportError:
    # Django not available, defer registration
    pass
