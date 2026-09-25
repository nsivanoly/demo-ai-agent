"""
The only way this demo reaches an MCP tool: through the Agent Manager gateway.

Two URLs, and they are deliberately not the same one.

  WHERE TO CALL       the gateway's in-cluster Kubernetes service. The vhost
                      Agent Manager publishes is a *.localhost name that
                      resolves on the operator's machine and nowhere inside the
                      cluster, so an agent that calls it gets DNS failure.
  WHAT TO BIND TO     the registered resource, which IS that external URL. RFC
                      8707 target-resource indication only accepts a resource
                      the identity provider has registered, so binding the
                      token to the in-cluster address fails with
                      `invalid_target`.

The token therefore says "meant for the gateway at its published address" while
travelling to the same gateway by its internal one. Both are set by the demo
setup; this module picks whichever address actually answers.

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
_chosen_url: Optional[str] = None


class GatewayError(RuntimeError):
    pass


def _candidates() -> List[str]:
    injected = next((v for k, v in os.environ.items()
                     if k.endswith("_MCP_CONFIG_URL") and v), "")
    seen, out = set(), []
    for u in (os.getenv("MCP_GATEWAY_URL", ""), injected,
              os.getenv("MCP_GATEWAY_URL_EXTERNAL", ""), os.getenv("MCP_RESOURCE", "")):
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def gateway_resource() -> str:
    """The OAuth 2.0 target resource the AgentID token must be bound to."""
    return (os.getenv("MCP_RESOURCE")
            or os.getenv("MCP_GATEWAY_URL_EXTERNAL")
            or next((v for k, v in os.environ.items()
                     if k.endswith("_MCP_CONFIG_URL") and v), "")
            or os.getenv("MCP_GATEWAY_URL", ""))


def gateway_url() -> str:
    """The gateway address that answers from wherever this is running.

    Any HTTP response counts as reachable, including 401 -- a gateway refusing
    an unauthenticated probe is a gateway that is there. Only DNS and connection
    failures move on to the next candidate. Probed once.
    """
    global _chosen_url
    if _chosen_url is not None:
        return _chosen_url
    cands = _candidates()
    for url in cands:
        try:
            httpx.post(url, json={"jsonrpc": "2.0", "id": 0, "method": "tools/list"},
                       timeout=8)
            _chosen_url = url
            return url
        except Exception:
            continue
    _chosen_url = cands[0] if cands else ""
    return _chosen_url


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


def endpoints() -> Dict[str, str]:
    """What this agent is using, for /whoami."""
    return {"calls": gateway_url(), "token_bound_to": gateway_resource(),
            "candidates": _candidates()}


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
