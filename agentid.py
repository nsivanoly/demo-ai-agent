"""
AgentID helper for platform-hosted WSO2 Agent Manager agents.

AMP injects these env vars into a platform-hosted agent; they are system-managed
and must not be set by hand:

    AMP_AGENTID_CLIENT_ID
    AMP_AGENTID_CLIENT_SECRET
    AMP_AGENTID_TOKEN_ENDPOINT
    AMP_AGENTID_SCOPES

The token comes from the OAuth 2.0 client_credentials grant. `resource` is
RFC 8707 target-resource indication -- ThunderID scopes the token to that one
resource, so tokens are cached per resource rather than globally. AMP filters
the granted scopes against the agent's assigned roles at mint time, so the
token that comes back is the authoritative statement of what this agent may do.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Dict, Optional, Tuple

import httpx

CLIENT_ID = os.getenv("AMP_AGENTID_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("AMP_AGENTID_CLIENT_SECRET", "")
TOKEN_ENDPOINT = os.getenv("AMP_AGENTID_TOKEN_ENDPOINT", "")
# AMP computes AMP_AGENTID_SCOPES when the agent is created, which is before
# any role is assigned, so it can arrive empty. AGENT_SCOPES is written by the
# demo setup after role assignment and takes precedence when present.
DEFAULT_SCOPES = os.getenv("AGENT_SCOPES") or os.getenv("AMP_AGENTID_SCOPES", "")
RESOURCE = os.getenv("MCP_RESOURCE", "http://default-default.gateway.localhost:19080/mcp")

_cache: Dict[Tuple[str, str], Tuple[str, float]] = {}
_lock = threading.Lock()


class AgentIDError(RuntimeError):
    pass


def configured() -> bool:
    return bool(CLIENT_ID and CLIENT_SECRET and TOKEN_ENDPOINT)


def get_token(scopes: Optional[str] = None, resource: Optional[str] = None) -> str:
    """Fetch (and cache) an AgentID access token for one resource."""
    if not configured():
        raise AgentIDError(
            "AgentID is not configured. AMP injects AMP_AGENTID_CLIENT_ID, "
            "AMP_AGENTID_CLIENT_SECRET and AMP_AGENTID_TOKEN_ENDPOINT into "
            "platform-hosted agents.")

    scope = scopes if scopes is not None else DEFAULT_SCOPES
    res = resource or RESOURCE
    key = (scope, res)

    with _lock:
        hit = _cache.get(key)
        if hit and hit[1] > time.time():
            return hit[0]

    data = {"grant_type": "client_credentials"}
    if scope:
        data["scope"] = scope
    if res:
        data["resource"] = res

    resp = httpx.post(TOKEN_ENDPOINT, data=data,
                      auth=(CLIENT_ID, CLIENT_SECRET), timeout=20)
    if resp.status_code >= 400:
        raise AgentIDError(f"token endpoint returned {resp.status_code}: {resp.text[:200]}")

    body = resp.json()
    token = body["access_token"]
    ttl = float(body.get("expires_in", 3600))     # refresh at 75% of lifetime
    with _lock:
        _cache[key] = (token, time.time() + ttl * 0.75)
    return token


def granted_scopes() -> str:
    return DEFAULT_SCOPES
