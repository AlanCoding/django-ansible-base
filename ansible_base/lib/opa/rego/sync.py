import json
import logging
import os
import threading

import requests

from ansible_base.lib.opa.rego.generator import generate_user_policies

logger = logging.getLogger(__name__)

_sync_lock = threading.Lock()
_sync_timer = None

BUNDLES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "bundles")


def sync_to_opa(debounce_seconds=0):
    """Sync generated policy data to OPA.

    Args:
        debounce_seconds: if > 0, debounce rapid calls by waiting this many
            seconds before actually syncing. Only the last call within the
            window takes effect.
    """
    if debounce_seconds > 0:
        _debounced_sync(debounce_seconds)
    else:
        _do_sync()


def _debounced_sync(seconds):
    """Schedule a sync after a delay, canceling any pending sync."""
    global _sync_timer
    with _sync_lock:
        if _sync_timer is not None:
            _sync_timer.cancel()
        _sync_timer = threading.Timer(seconds, _do_sync)
        _sync_timer.daemon = True
        _sync_timer.start()


def _do_sync():
    """Generate policy data and push to OPA."""
    global _sync_timer
    with _sync_lock:
        _sync_timer = None

    user_policies = generate_user_policies()

    # Write data.json to bundles dir for reference/debugging
    _write_data_json(user_policies)

    # Push to OPA via Data API
    _push_to_opa(user_policies)


def _write_data_json(user_policies):
    """Write the generated data to bundles/data.json for reference."""
    data = {"dab_opa": {"user_policies": user_policies}}
    data_path = os.path.join(BUNDLES_DIR, "data.json")
    try:
        with open(data_path, "w") as f:
            json.dump(data, f, indent=2)
        logger.debug("Wrote OPA data to %s", data_path)
    except OSError:
        logger.exception("Failed to write OPA data.json")


def _push_to_opa(user_policies):
    """Push policy data to OPA via the Data API."""
    from ansible_base.lib.opa.registry import opa_registry

    url = f"{opa_registry.server_url}/v1/data/dab_opa/user_policies"
    try:
        resp = requests.put(url, json=user_policies, timeout=10)
        resp.raise_for_status()
        logger.info("Pushed policy data to OPA (%d users)", len(user_policies))
    except requests.RequestException:
        logger.exception("Failed to push policy data to OPA at %s", url)
