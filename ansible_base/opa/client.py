import logging
import os

import requests

logger = logging.getLogger(__name__)

DEFAULT_OPA_URL = "http://localhost:8181"


class OPAClient:
    """HTTP client for querying OPA."""

    def __init__(self, base_url=None):
        self.base_url = base_url or os.environ.get("DAB_OPA_SERVER_URL", DEFAULT_OPA_URL)

    def health(self):
        """Check if OPA is reachable and healthy."""
        resp = requests.get(f"{self.base_url}/health", timeout=5)
        resp.raise_for_status()
        return True

    def query(self, user_id, is_superuser, resource, action):
        """Query OPA for resolved clauses.

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
            }
        }
        try:
            resp = requests.post(
                f"{self.base_url}/v1/data/dab_opa",
                json=payload,
                timeout=5,
            )
            resp.raise_for_status()
            result = resp.json().get("result", {})
            return {
                "allow": result.get("allow", False),
                "clauses": result.get("clauses", []),
            }
        except requests.RequestException:
            logger.exception("OPA query failed, failing closed (deny all)")
            return {"allow": False, "clauses": []}

    def check_object(self, user_id, is_superuser, resource, action, obj_attrs, related=None):
        """Tier 2: Check if a user can perform an action on a specific object.

        Args:
            user_id: the user's PK
            is_superuser: bool
            resource: OPA resource name
            action: OPA action string
            obj_attrs: dict of the object's field values (registered fields)
            related: optional dict of field_name -> {resource, action, id, org_id}

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
            }
        }
        if related:
            payload["input"]["related"] = related

        try:
            resp = requests.post(
                f"{self.base_url}/v1/data/dab_opa",
                json=payload,
                timeout=5,
            )
            resp.raise_for_status()
            result = resp.json().get("result", {})
            return {
                "object_allowed": result.get("object_allowed", False),
                "related_denied": set(result.get("related_denied", [])),
            }
        except requests.RequestException:
            logger.exception("OPA object check failed, failing closed (deny all)")
            return {"object_allowed": False, "related_denied": set()}
