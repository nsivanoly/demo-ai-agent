"""
Payments Agent -- the confidential-tier specialist.

Runs as a platform-hosted WSO2 Agent Manager agent with its own real AgentID.
It is reached only through a delegated credential from the concierge agent, and
it never sees a card number: it passes an opaque vault reference to the tool,
and the vault de-tokenises internally.
"""

from __future__ import annotations

import base64
import json
import os
import uuid
from typing import Any, Dict, Optional

import httpx
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

import agentid

app = FastAPI(title="Payments Agent", version="1.0.0")

AGENT_ID = os.getenv("AGENT_NAME", "payments-agent")
RUNTIME = os.getenv("AGENT_RUNTIME", "runtime-b")
MCP_URL = os.getenv("MCP_URL", "http://host.k3d.internal:8892/mcp")
# resolved lazily so the AMP-injected gateway URL is preferred when usable
CONFIDENTIAL_TOOL = os.getenv("CONFIDENTIAL_TOOL", "configure_workflow")
_GW_OK = None


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


def claims_of(token: str) -> Dict[str, Any]:
    try:
        p = token.split(".")[1]
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception:
        return {}


class SettleRequest(BaseModel):
    delegated_token: str
    amount: float
    payment_ref: str = "tok_card_9931"
    user: str = "alice@example.com"
    trace_id: Optional[str] = None


@app.post("/settle")
async def settle(req: SettleRequest):
    """Act under the delegated credential, on a vault reference only."""
    trace_id = req.trace_id or ("txn-" + uuid.uuid4().hex[:16])
    c = claims_of(req.delegated_token)
    chain = c.get("delegation_chain") or [c.get("act", {}).get("sub"), AGENT_ID]

    async with httpx.AsyncClient(timeout=30) as client:
        out = await client.post(
            mcp_url(),
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                  "params": {"name": CONFIDENTIAL_TOOL,
                             "arguments": {"payment_ref": req.payment_ref,
                                           "amount": req.amount}}},
            headers={"Authorization": f"Bearer {req.delegated_token}",
                     "X-Agent-Runtime": RUNTIME, "X-Trace-Id": trace_id})

    body = out.json()
    return {"status": "ok" if "result" in body else "denied",
            "agent": AGENT_ID, "trace_id": trace_id,
            "delegation_chain": chain,
            "credential": c.get("cred_kind", "DEMO"),
            "payment_ref_used": req.payment_ref,
            "card_number_seen_by_agent": None,
            "mcp_response": body}


@app.get("/whoami")
async def whoami():
    info = {"agent": AGENT_ID, "runtime": RUNTIME,
            "agentid_configured": agentid.configured(),
            "scopes_from_amp": agentid.granted_scopes(),
            "mcp_gateway_url": _gateway_url() or None,
            "mcp_gateway_usable": _gateway_usable(_gateway_url()),
            "mcp_endpoint_in_use": mcp_url(),
            "via_amp_gateway": mcp_url() == _gateway_url() and bool(_gateway_url())}
    if agentid.configured():
        try:
            info["token_claims"] = {
                k: v for k, v in claims_of(mcp_token()).items()
                if k in ("sub", "scope", "aud", "iss", "exp")}
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
