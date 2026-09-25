"""
Concierge Agent -- the user-facing orchestrator.

Runs as a platform-hosted WSO2 Agent Manager agent. Its identity is a real
AgentID: AMP injects the client credentials, the agent exchanges them for an
access token, and AMP filters the scopes in that token against the roles the
agent has been assigned.

It deliberately does NOT hold the confidential-tier scope. Work that needs it
is delegated to the payments agent -- which is the point of the delegation
scenario, and a capability AMP v1.0.0 has no primitive for (hence the broker).
"""

from __future__ import annotations

import os
import uuid
from typing import Any, Dict, List, Optional

import httpx
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

import agentid

app = FastAPI(title="Concierge Agent", version="1.0.0")

AGENT_ID = os.getenv("AGENT_NAME", "concierge-agent")
RUNTIME = os.getenv("AGENT_RUNTIME", "runtime-a")
MCP_URL = os.getenv("MCP_URL", "http://host.k3d.internal:8892/mcp")
# resolved lazily so the AMP-injected gateway URL is preferred when usable
BROKER_URL = os.getenv("BROKER_URL", "http://host.k3d.internal:8890")
PAYMENTS_URL = os.getenv("PAYMENTS_AGENT_URL", "http://host.k3d.internal:8894")
LOW_TOOL = os.getenv("LOW_TOOL", "process_order")
_GW_OK = None
CONFIDENTIAL_SCOPE = os.getenv("CONFIDENTIAL_SCOPE", "")


def _gateway_url() -> str:
    """The MCP gateway URL AMP injects for this agent's proxy binding."""
    return next((v for k, v in os.environ.items()
                 if k.endswith("_MCP_CONFIG_URL") and v), "")


def _gateway_usable(url: str) -> bool:
    """Is the AMP gateway actually serving the MCP proxy?

    On builds where the proxy has not reconciled onto the gateway there is no
    Mcp artifact, so the route 404s -- and the injected hostname does not even
    resolve from inside the cluster. Probe once and cache.
    """
    global _GW_OK
    if _GW_OK is not None:
        return _GW_OK
    _GW_OK = False
    if url:
        try:
            r = httpx.post(url, json={"jsonrpc": "2.0", "id": 0,
                                      "method": "tools/list"}, timeout=5)
            _GW_OK = r.status_code < 400
        except Exception:
            _GW_OK = False
    return _GW_OK


def mcp_url() -> str:
    """The MCP endpoint this agent calls.

    Prefer the AMP gateway, so the gateway performs the authorization. That URL
    is also the OAuth 2.0 target resource (RFC 8707) the token is bound to, so
    it has to be settled before the token is minted, not just before the call.

    Falls back to the enforcement point directly when the gateway is not
    serving the proxy, so the demo still runs; /whoami reports which is in use.
    """
    gw = _gateway_url()
    if _gateway_usable(gw):
        return gw
    return os.getenv("MCP_URL", "http://host.k3d.internal:8892/mcp")


def mcp_token() -> str:
    """An AgentID token bound to the MCP resource registered in AMP.

    The RFC 8707 resource must be a target AMP knows about -- the gateway URL
    from the proxy binding. Binding it to the direct fallback URL instead makes
    the token endpoint reject the request with 400, because that URL is not a
    registered resource. So the resource stays the gateway URL even when the
    call itself falls back to the enforcement point.
    """
    resource = _gateway_url() or os.getenv("MCP_RESOURCE", "")
    return agentid.get_token(resource=resource or None)


def new_trace() -> str:
    return "txn-" + uuid.uuid4().hex[:16]


async def call_tool(client: httpx.AsyncClient, token: str, trace_id: str,
                    tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
    r = await client.post(mcp_url(),
                          json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                "params": {"name": tool, "arguments": args}},
                          headers={"Authorization": f"Bearer {token}",
                                   "X-Agent-Runtime": RUNTIME,
                                   "X-Trace-Id": trace_id})
    return r.json()


class TaskRequest(BaseModel):
    user: str = "alice@example.com"
    intent: str = "pay"
    order_id: Optional[str] = "ORD-77001"
    customer_id: Optional[str] = "CUST-1001"
    amount: Optional[float] = 249.00
    payment_ref: str = "tok_card_9931"
    trace_id: Optional[str] = None


@app.post("/task")
async def task(req: TaskRequest):
    """User -> this agent. It does what its own scopes allow, delegates the rest."""
    trace_id = req.trace_id or new_trace()
    steps: List[Dict[str, Any]] = []

    try:
        token = mcp_token()
    except agentid.AgentIDError as exc:
        return {"trace_id": trace_id, "status": "failed", "at": "agentid",
                "detail": str(exc)}
    steps.append({"hop": "agentid", "action": "AgentID token minted",
                  "scopes": agentid.granted_scopes(), "credential": "AMP",
                  "resource": mcp_url()})

    async with httpx.AsyncClient(timeout=30) as client:
        # --- work this agent is entitled to do itself --------------------
        out = await call_tool(client, token, trace_id, LOW_TOOL,
                              {"order_id": req.order_id, "name": req.user})
        steps.append({"hop": "agent -> mcp", "tool": LOW_TOOL, "result": out})

        if req.intent != "pay":
            return {"trace_id": trace_id, "status": "ok", "agent": AGENT_ID, "steps": steps}

        # --- work it is NOT entitled to do: delegate ----------------------
        d = await client.post(f"{BROKER_URL}/agents/{AGENT_ID}/delegate",
                              json={"to_agent": "payments-agent",
                                    "scopes": [CONFIDENTIAL_SCOPE],
                                    "user": req.user, "trace_id": trace_id})
        if d.status_code != 200:
            steps.append({"hop": "agent -> broker", "action": "delegate",
                          "decision": "DENY", "detail": d.json()})
            return {"trace_id": trace_id, "status": "failed", "at": "delegation",
                    "steps": steps}

        dj = d.json()
        steps.append({"hop": "agent -> broker", "action": "delegate", "decision": "ALLOW",
                      "delegation_chain": dj["delegation_chain"],
                      "delegated_scope": dj["scope"], "credential": "DEMO"})

        b = await client.post(f"{PAYMENTS_URL}/settle",
                              json={"delegated_token": dj["access_token"],
                                    "amount": req.amount, "payment_ref": req.payment_ref,
                                    "user": req.user, "trace_id": trace_id})
        steps.append({"hop": "agent -> payments-agent", "result": b.json()})

    return {"trace_id": trace_id, "status": "ok", "agent": AGENT_ID, "steps": steps}


class SpawnRequest(BaseModel):
    purpose: str = "summarise recent orders"
    scopes: List[str] = []
    ttl_seconds: int = 30
    trace_id: Optional[str] = None


@app.post("/spawn")
async def spawn(req: SpawnRequest):
    """Ask the broker for a short-lived child identity with a subset of scopes."""
    trace_id = req.trace_id or new_trace()
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(f"{BROKER_URL}/agents/{AGENT_ID}/subagents",
                              json={"purpose": req.purpose, "scopes": req.scopes,
                                    "ttl_seconds": req.ttl_seconds, "trace_id": trace_id})
    return {"trace_id": trace_id, "status": r.status_code, "body": r.json()}


@app.get("/whoami")
async def whoami():
    """What this agent's real AMP identity actually permits."""
    info = {"agent": AGENT_ID, "runtime": RUNTIME,
            "agentid_configured": agentid.configured(),
            "scopes_from_amp": agentid.granted_scopes(),
            "mcp_gateway_url": _gateway_url() or None,
            "mcp_gateway_usable": _gateway_usable(_gateway_url()),
            "mcp_endpoint_in_use": mcp_url(),
            "via_amp_gateway": mcp_url() == _gateway_url() and bool(_gateway_url())}
    if agentid.configured():
        try:
            import base64, json
            p = mcp_token().split(".")[1]
            p += "=" * (-len(p) % 4)
            c = json.loads(base64.urlsafe_b64decode(p))
            info["token_claims"] = {k: c.get(k) for k in ("sub", "scope", "aud", "iss", "exp")}
        except Exception as exc:
            info["token_error"] = str(exc)
    return info


@app.get("/health")
async def health():
    return {"status": "ok", "service": AGENT_ID}


if __name__ == "__main__":
    # AMP's inputInterface declares port 8000 and its readiness probe is a TCP
    # check on 8000. The Google buildpack sets PORT=8080 in the image, so
    # binding $PORT makes the probe fail and the pod is SIGTERMed. Bind 8000.
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("AGENT_PORT", "8000")),
                log_level="info")
