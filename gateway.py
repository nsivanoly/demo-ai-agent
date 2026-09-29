"""
Calls to the MCP gateway, the only route to a tool.

Addresses: the MCP URL is the one Agent Manager injects for the attached MCP
server (see bindings.py). It is a *.localhost URL, which resolves on the host but
not inside the cluster, so setup writes the in-cluster gateway address as
GATEWAY_INTERNAL_BASE and `internal()` rewrites the injected URL onto it: the
token audience stays the injected URL, the call goes where the pod can reach.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx

from identity import MCP_RESOURCE, UA

GATEWAY_INTERNAL_BASE = os.getenv("GATEWAY_INTERNAL_BASE", "").rstrip("/")


def internal(url: str) -> str:
    """Rewrite an injected external gateway URL to the in-cluster gateway."""
    if not url or not GATEWAY_INTERNAL_BASE:
        return url
    p = urlparse(url)
    if p.hostname and p.hostname.endswith(".localhost"):
        return GATEWAY_INTERNAL_BASE + p.path
    return url


MCP_GATEWAY_URL = internal(MCP_RESOURCE) or os.getenv("MCP_GATEWAY_URL", "")   # in-cluster address to call


def call_tool(token: str, tool: str, args: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    """One tools/call through the gateway. Returns a normalised decision:

    {"allowed", "decided_by": gateway|server|-, "status", "result", "reason"}
    """
    payload = dict(args)
    payload["ctx"] = json.dumps(ctx, separators=(",", ":"))
    try:
        r = httpx.post(MCP_GATEWAY_URL, timeout=45, headers={
            "Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream",
            "User-Agent": UA, "X-Transaction-Id": str(ctx.get("txn", ""))},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": payload}})
    except httpx.HTTPError as e:
        return {"allowed": False, "decided_by": "-", "status": 0, "reason": f"gateway unreachable: {e}", "result": None}
    try:
        body = r.json()
    except ValueError:
        body = {"raw": r.text[:300]}
    if r.status_code in (401, 403):
        return {"allowed": False, "decided_by": "gateway", "status": r.status_code, "result": None,
                "reason": body.get("message") or body.get("error") or r.text[:200]}
    if r.status_code >= 400:
        return {"allowed": False, "decided_by": "-", "status": r.status_code, "result": None, "reason": r.text[:200]}
    res = body.get("result") or {}
    if body.get("error") or res.get("isError"):
        text = (res.get("content") or [{}])[0].get("text", "") if res else str(body.get("error"))
        return {"allowed": False, "decided_by": "server", "status": r.status_code, "result": None,
                "reason": text[:400], "detail": _maybe_json(text)}
    data = res.get("structuredContent")
    if data is None:
        data = _maybe_json((res.get("content") or [{}])[0].get("text", ""))
    return {"allowed": True, "decided_by": "gateway+server", "status": r.status_code, "result": data, "reason": "allowed"}


def _maybe_json(text: str) -> Optional[Any]:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return text or None
