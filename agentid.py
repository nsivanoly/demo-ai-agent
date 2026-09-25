"""
AgentID helper for platform-hosted WSO2 Agent Manager agents.

AMP injects these into a platform-hosted agent; they are system-managed and
must never be set by hand:

    AMP_AGENTID_CLIENT_ID
    AMP_AGENTID_CLIENT_SECRET
    AMP_AGENTID_TOKEN_ENDPOINT
    AMP_AGENTID_SCOPES

The token comes from the OAuth 2.0 client_credentials grant. `resource` is
RFC 8707 target-resource indication: the token is bound to the endpoint it will
be presented to, which is how the gateway knows the token was meant for it.
That endpoint has to be a resource the identity provider has registered -- the
MCP proxy's gateway URL -- otherwise the token endpoint answers

    {"error":"invalid_target",
     "error_description":"The resource parameter does not match any
                          registered resource server"}

AMP filters the granted scopes against the agent's assigned roles at mint time,
so the token that comes back is the authoritative statement of what this agent
may do. Asking for more than the roles allow does not fail -- the extra scopes
are simply absent from the response.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
from typing import Any, Dict, Optional, Tuple

import httpx

CLIENT_ID = os.getenv("AMP_AGENTID_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("AMP_AGENTID_CLIENT_SECRET", "")
TOKEN_ENDPOINT = os.getenv("AMP_AGENTID_TOKEN_ENDPOINT", "")
# AMP computes AMP_AGENTID_SCOPES when the agent is created, which is before
# any role is assigned, so it can arrive empty. AGENT_SCOPES is written by the
# demo setup after role assignment and takes precedence when present.
DEFAULT_SCOPES = os.getenv("AGENT_SCOPES") or os.getenv("AMP_AGENTID_SCOPES", "")

_cache: Dict[Tuple[str, str], Tuple[str, float]] = {}
_lock = threading.Lock()


class AgentIDError(RuntimeError):
    pass


def configured() -> bool:
    return bool(CLIENT_ID and CLIENT_SECRET and TOKEN_ENDPOINT)


def claims(token: str) -> Dict[str, Any]:
    try:
        p = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return {}


def get_token(scopes: Optional[str] = None, resource: str = "") -> str:
    """Fetch (and cache) an AgentID access token for one resource."""
    if not configured():
        raise AgentIDError(
            "AgentID is not configured. AMP injects AMP_AGENTID_CLIENT_ID, "
            "AMP_AGENTID_CLIENT_SECRET and AMP_AGENTID_TOKEN_ENDPOINT into "
            "platform-hosted agents.")

    scope = DEFAULT_SCOPES if scopes is None else scopes
    key = (scope, resource)
    with _lock:
        hit = _cache.get(key)
        if hit and hit[1] > time.time():
            return hit[0]

    data = {"grant_type": "client_credentials"}
    if scope:
        data["scope"] = scope
    if resource:
        data["resource"] = resource

    resp = httpx.post(TOKEN_ENDPOINT, data=data,
                      auth=(CLIENT_ID, CLIENT_SECRET), timeout=20)
    if resp.status_code >= 400:
        raise AgentIDError(f"token endpoint returned {resp.status_code}: {resp.text[:200]}")

    body = resp.json()
    token = body["access_token"]
    ttl = float(body.get("expires_in", 3600))
    with _lock:                                   # refresh at 75% of lifetime
        _cache[key] = (token, time.time() + ttl * 0.75)
    return token


def granted_scopes() -> str:
    return DEFAULT_SCOPES


def forget() -> None:
    """Drop cached tokens -- used after a role change so the next mint is fresh."""
    with _lock:
        _cache.clear()
