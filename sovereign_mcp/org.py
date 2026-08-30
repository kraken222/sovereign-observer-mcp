"""Fetches an organization's custom policy rules — the one network call.

The privacy promise this package makes is that the developer's Terraform never
leaves their machine. Org policy has to reconcile with that, and it does,
because of the direction of travel: **rules come down, code never goes up.**

That invariant is structural here, not a matter of discipline. This module
issues a GET with no body, and it is the only place in the package that opens a
socket at all. ``tests/test_org_policy.py`` asserts both.

Without ``SOVEREIGN_TOKEN`` set, nothing here runs and the server stays fully
local — which is the free tier, and stays the free tier.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

DEFAULT_API_BASE = "https://sovereign-api.onrender.com"
CACHE_TTL_SECONDS = 900
REQUEST_TIMEOUT = 15

_cache: Dict[str, Any] = {"fetched_at": 0.0, "payload": None, "error": None}


class OrgPolicyError(RuntimeError):
    """Fetching org policy failed in a way the developer should see."""


def token() -> Optional[str]:
    """The org token, or None when this is an unconnected (free) install."""
    for name in ("SOVEREIGN_TOKEN", "SOVEREIGN_PR_TOKEN"):
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return None


def api_base() -> str:
    return (os.environ.get("SOVEREIGN_API_URL") or DEFAULT_API_BASE).rstrip("/")


def is_connected() -> bool:
    return token() is not None


def clear_cache() -> None:
    _cache.update({"fetched_at": 0.0, "payload": None, "error": None})


def fetch_policy(force: bool = False) -> Optional[Dict[str, Any]]:
    """Return the org's policy payload, or None when not connected.

    Cached in memory for the life of the process — a stdio server lives as long
    as the editor session, so one fetch per session is the right cadence.
    Nothing is written to disk: org policy is the customer's security posture
    and does not belong in a cache file on a laptop.
    """
    auth = token()
    if not auth:
        return None

    fresh = (time.time() - _cache["fetched_at"]) < CACHE_TTL_SECONDS
    if not force and fresh and _cache["payload"] is not None:
        return _cache["payload"]

    url = f"{api_base()}/api/iac/org-policy"
    request = urllib.request.Request(
        url,
        method="GET",  # GET, and no data= — see the module docstring.
        headers={
            "Authorization": f"Bearer {auth}",
            "Accept": "application/json",
            "User-Agent": "sovereign-mcp",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise OrgPolicyError(_http_message(exc)) from exc
    except urllib.error.URLError as exc:
        raise OrgPolicyError(
            f"Could not reach {api_base()} ({exc.reason}). Built-in rules still "
            "apply — only your organization's custom rules are unavailable."
        ) from exc
    except (ValueError, TimeoutError) as exc:
        raise OrgPolicyError(f"Malformed response from {url}: {exc}") from exc

    _cache.update({"fetched_at": time.time(), "payload": payload, "error": None})
    return payload


def _http_message(exc: urllib.error.HTTPError) -> str:
    """Turn an HTTP failure into something the developer can act on."""
    if exc.code == 401:
        return (
            "SOVEREIGN_TOKEN was rejected. Generate a new org token from "
            "Integrations in the dashboard."
        )
    if exc.code == 403:
        return (
            "Custom organization policies are not included in this plan. The "
            "built-in rules still run locally."
        )
    if exc.code == 400:
        return (
            "This token is not bound to an organization. Generate an org token "
            "from Integrations in the dashboard."
        )
    return f"Org policy request failed ({exc.code})."


def rules(provider: Optional[str] = None) -> List[Dict[str, Any]]:
    """The org's rule dicts, optionally filtered to one cloud provider."""
    payload = fetch_policy()
    if not payload:
        return []
    found = payload.get("rules") or []
    if provider:
        wanted = provider.strip().lower()
        return [r for r in found if (r.get("provider") or "").lower() == wanted]
    return found


def status() -> Dict[str, Any]:
    """Connection state, safe to call whether or not a token is configured."""
    if not is_connected():
        return {
            "connected": False,
            "mode": "local",
            "detail": (
                "No SOVEREIGN_TOKEN configured. Built-in security rules run "
                "locally; no organization policy is applied and nothing is sent "
                "anywhere."
            ),
        }
    try:
        payload = fetch_policy() or {}
    except OrgPolicyError as exc:
        return {
            "connected": False,
            "mode": "local",
            "error": str(exc),
            "detail": "Built-in rules are still running locally.",
        }
    return {
        "connected": True,
        "mode": "org",
        "org_name": payload.get("org_name"),
        "rule_count": payload.get("rule_count", 0),
        "providers": payload.get("providers") or [],
        "policy_version": payload.get("policy_version"),
        "skipped_policies": payload.get("skipped_policies"),
    }
