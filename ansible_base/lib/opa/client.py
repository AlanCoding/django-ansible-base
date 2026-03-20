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
