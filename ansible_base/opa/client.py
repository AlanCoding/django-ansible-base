import json
import logging
import os
import time

import requests

logger = logging.getLogger(__name__)

DEFAULT_OPA_URL = "http://localhost:8181"

# File-based request/response logging for OPA interactions.
# Set DAB_OPA_LOG_FILE to a path to enable. Each entry is a JSON object
# with timestamp, method, url, request payload, response, and duration.
_OPA_LOG_FILE = os.environ.get("DAB_OPA_LOG_FILE")


def _log_opa_interaction(method, url, payload, response_data, duration_ms, status_code):
    """Append an OPA request/response record to the log file."""
    if not _OPA_LOG_FILE:
        return
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "method": method,
        "url": url,
        "request": payload,
        "response": response_data,
        "status_code": status_code,
        "duration_ms": round(duration_ms, 2),
    }
    try:
        with open(_OPA_LOG_FILE, "a") as f:
            f.write(json.dumps(entry, indent=2, default=str) + "\n")
    except OSError:
        logger.debug("Failed to write OPA log entry to %s", _OPA_LOG_FILE)


class OPAClient:
    """HTTP client for querying OPA."""

    def __init__(self, base_url=None):
        self.base_url = base_url or os.environ.get("DAB_OPA_SERVER_URL", DEFAULT_OPA_URL)

    def health(self):
        """Check if OPA is reachable and healthy."""
        resp = requests.get(f"{self.base_url}/health", timeout=5)
        resp.raise_for_status()
        return True

    def query(self, user_id, is_superuser, resource, action, policies):
        """Query OPA for resolved clauses.

        Args:
            user_id: the user's PK
            is_superuser: bool
            resource: OPA resource name
            action: OPA action string
            policies: list of unresolved clause dicts (with value_type)

        Returns a dict with 'allow' (bool) and 'clauses' (list).
        On error, fails closed (deny all).
        """
        payload = {
            "input": {
                "principal": {
                    "user_id": user_id,
                    "is_superuser": is_superuser,
                },
                "target": {
                    "resource": resource,
                    "action": action,
                },
                "policies": policies,
            }
        }
        url = f"{self.base_url}/v1/data/dab_opa"
        try:
            t0 = time.monotonic()
            resp = requests.post(url, json=payload, timeout=5)
            duration_ms = (time.monotonic() - t0) * 1000
            resp.raise_for_status()
            raw = resp.json()
            result = raw.get("result", {})
            out = {
                "allow": result.get("allow", False),
                "clauses": result.get("clauses", []),
            }
            _log_opa_interaction("POST", url, payload, raw, duration_ms, resp.status_code)
            return out
        except requests.RequestException:
            logger.exception("OPA query failed, failing closed (deny all)")
            return {"allow": False, "clauses": []}

    def check_object(self, user_id, is_superuser, resource, action, obj_attrs, policies, related=None):
        """Tier 2: Check if a user can perform an action on a specific object.

        Args:
            user_id: the user's PK
            is_superuser: bool
            resource: OPA resource name
            action: OPA action string
            obj_attrs: dict of the object's field values (registered fields)
            policies: list of unresolved clause dicts (with value_type)
            related: optional dict of field_name -> {resource, action, id, org_id, policies}

        Returns:
            Dict with 'object_allowed' (bool) and 'related_denied' (set of field names).
        """
        payload = {
            "input": {
                "principal": {
                    "user_id": user_id,
                    "is_superuser": is_superuser,
                },
                "target": {
                    "resource": resource,
                    "action": action,
                },
                "object": obj_attrs,
                "policies": policies,
            }
        }
        if related:
            payload["input"]["related"] = related

        url = f"{self.base_url}/v1/data/dab_opa"
        try:
            t0 = time.monotonic()
            resp = requests.post(url, json=payload, timeout=5)
            duration_ms = (time.monotonic() - t0) * 1000
            resp.raise_for_status()
            raw = resp.json()
            result = raw.get("result", {})
            out = {
                "object_allowed": result.get("object_allowed", False),
                "related_denied": set(result.get("related_denied", [])),
            }
            _log_opa_interaction("POST", url, payload, raw, duration_ms, resp.status_code)
            return out
        except requests.RequestException:
            logger.exception("OPA object check failed, failing closed (deny all)")
            return {"object_allowed": False, "related_denied": set()}
