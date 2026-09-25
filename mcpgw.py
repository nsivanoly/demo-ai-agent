"""
The only way this demo reaches an MCP tool: through the Agent Manager gateway.

AMP injects the gateway URL for the agent's MCP proxy binding as
<CONFIG>_MCP_CONFIG_URL. That URL is both the endpoint and the OAuth 2.0 target
resource the AgentID token is bound to, so it has to be settled before the
token is minted -- not just before the call.

There is no direct-to-server fallback, deliberately. The gateway is the policy
enforcement point; a fallback that bypasses it would make the demo prove
something weaker than it claims. If the gateway is not serving the proxy the
call fails, loudly, and the setup output says why.

The hosting platform in front of the MCP server runs it over stdio, so HTTP
request headers never reach it. Caller context therefore travels as a `ctx`
tool argument when the server's schema accepts one -- asserted context for the
audit record, not a credential. Authorization has already happened at the
gateway by then.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import httpx

_ctx_tools: Optional[set] = None


class GatewayError(RuntimeError):
    pass


def gateway_url() -> str:
    """The MCP gateway URL AMP injected for this agent's proxy binding."""
    injected = next((v for k, v in os.environ.items()
                     if k.endswith("_MCP_CONFIG_URL") and v), "")
    return injected or os.getenv("MCP_GATEWAY_URL", "")


def _rpc(url: str, token: str, method: str, params: Any,
         trace_id: str = "") -> Dict[str, Any]:
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if trace_id:
        headers["X-Trace-Id"] = trace_id
    body: Dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        body["params"] = params
    r = httpx.post(url, json=body, headers=headers, timeout=45)
    try:
        payload = r.json()
    except Exception:
        payload = {"error": {"code": r.status_code, "message": r.text[:200]}}
    payload["_http_status"] = r.status_code
    return payload


def supports_ctx(url: str, token: str) -> bool:
    """Does the deployed server accept a `ctx` argument?

    The server gained it so calls could be attributed under stdio hosting. An
    older deployment will not have it, and sending an unexpected argument would
    fail the call -- so this checks the advertised schema once and caches.
    """
    global _ctx_tools
    if _ctx_tools is not None:
        return bool(_ctx_tools)
    _ctx_tools = set()
    try:
        out = _rpc(url, token, "tools/list", None)
        for t in (out.get("result") or {}).get("tools", []):
            props = (t.get("inputSchema") or {}).get("properties") or {}
            if "ctx" in props:
                _ctx_tools.add(t["name"])
    except Exception:
        pass
    return bool(_ctx_tools)


def call_tool(token: str, tool: str, args: Dict[str, Any], *,
              trace_id: str = "", context: Optional[Dict[str, Any]] = None,
              url: str = "") -> Dict[str, Any]:
    """Call one tool through the gateway. Never touches the server directly."""
    target = url or gateway_url()
    if not target:
        raise GatewayError(
            "no MCP gateway URL: AMP injects <CONFIG>_MCP_CONFIG_URL when the "
            "agent is bound to an MCP proxy, and the demo setup writes "
            "MCP_GATEWAY_URL as a fallback. Neither is present.")

    payload = dict(args)
    if context is not None and supports_ctx(target, token) and tool in (_ctx_tools or ()):
        payload["ctx"] = json.dumps(context, separators=(",", ":"))

    return _rpc(target, token, "tools/call",
                {"name": tool, "arguments": payload}, trace_id)


def decision(out: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a tool response into an authorization outcome.

    Three shapes matter and they come from different places:

      403 from the gateway   the token lacked the scope the tool needs. This is
                             AMP's decision, made before the server was reached.
      401 from the gateway   the token was missing, expired or not for this
                             resource.
      isError in the result  the server ran the call and a guardrail, the
                             anomaly signal or the vault refused it.
    """
    status = out.get("_http_status", 0)
    if status == 403:
        return {"allowed": False, "by": "gateway", "status": status,
                "reason": out.get("message") or "insufficient scope for this tool"}
    if status == 401:
        return {"allowed": False, "by": "gateway", "status": status,
                "reason": out.get("message") or "token rejected"}
    if "error" in out:
        e = out["error"] or {}
        return {"allowed": False, "by": "server", "status": status,
                "reason": e.get("message", "")}
    result = out.get("result") or {}
    if result.get("isError"):
        text = ""
        for c in result.get("content", []):
            text += c.get("text", "")
        return {"allowed": False, "by": "server", "status": status, "reason": text}
    return {"allowed": True, "by": "gateway+server", "status": status,
            "reason": "allowed", "result": result.get("structuredContent")
            or result.get("content")}
