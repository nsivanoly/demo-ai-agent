"""
Payments Agent -- the confidential-tier specialist.

Runs as a platform-hosted WSO2 Agent Manager agent with its own real AgentID
and the only role that carries the confidential scope. It is reached through an
on-behalf-of assertion from the concierge agent, never directly by a user.

The important detail in the exchange: the assertion the concierge sends is NOT
what goes to the gateway. This agent verifies the assertion to establish who
asked and under whose authority, and then mints its OWN AgentID token for the
MCP call. That is what the gateway will accept -- the scopes in it come from
this agent's AMP roles, not from anything the caller asserted. A forged or
widened assertion gets this agent to act, at most, within its own grant.

It never sees a card number either. It passes an opaque vault reference and the
server de-tokenises internally, returning a masked receipt.
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, Header
from pydantic import BaseModel

import agentid
import mcpgw
import obo

app = FastAPI(title="Payments Agent", version="2.0.0")

AGENT_ID = os.getenv("AGENT_NAME", "demo2-payments-agent")
RUNTIME = os.getenv("AGENT_RUNTIME", "runtime-b")
CONFIDENTIAL_TOOL = os.getenv("CONFIDENTIAL_TOOL", "charge_card")
TRUSTED_DELEGATORS = [s for s in os.getenv(
    "TRUSTED_DELEGATORS", "demo2-concierge-agent").split(",") if s.strip()]


def hop(steps: List[Dict[str, Any]], name: str, credential: str,
        decision: str, detail: str, **extra: Any) -> Dict[str, Any]:
    row = {"hop": name, "credential": credential, "decision": decision,
           "detail": detail,
           "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    row.update(extra)
    steps.append(row)
    return row


def token_view(tok: str) -> Dict[str, Any]:
    c = agentid.claims(tok)
    return {k: c.get(k) for k in ("iss", "sub", "aud", "scope", "exp")
            if c.get(k) is not None}


class SettleRequest(BaseModel):
    amount: float = 249.00
    payment_ref: str = "tok_card_9931"
    trace_id: Optional[str] = None


@app.post("/settle")
async def settle(req: SettleRequest,
                 authorization: Optional[str] = Header(default=None)):
    """Act under a verified on-behalf-of assertion, on a vault reference only."""
    trace_id = req.trace_id or ("txn-" + uuid.uuid4().hex[:16])
    steps: List[Dict[str, Any]] = []

    assertion = (authorization or "")[7:] if (authorization or "").lower().startswith("bearer ") else ""
    if not assertion:
        hop(steps, "agent -> agent", "DEMO", "DENY",
            "no on-behalf-of assertion presented")
        return {"status": "denied", "at": "obo", "trace_id": trace_id, "steps": steps}

    # ---- verify the delegation ------------------------------------------
    try:
        c = obo.verify(assertion, audience=AGENT_ID)
    except obo.OBOError as exc:
        hop(steps, "agent -> obo verify", "DEMO", "DENY", str(exc),
            actor=AGENT_ID, presented=obo.claims(assertion).get("act"))
        return {"status": "denied", "at": "obo", "trace_id": trace_id,
                "reason": str(exc), "steps": steps}

    delegator = (c.get("act") or {}).get("sub", "")
    if delegator not in TRUSTED_DELEGATORS:
        hop(steps, "agent -> obo verify", "DEMO", "DENY",
            f"'{delegator}' is not in this agent's trusted delegators",
            actor=AGENT_ID, trusted=TRUSTED_DELEGATORS)
        return {"status": "denied", "at": "obo", "trace_id": trace_id,
                "reason": f"delegation from '{delegator}' is not accepted",
                "steps": steps}

    hop(steps, "agent -> obo verify", "DEMO", "ALLOW",
        f"assertion from {delegator} on behalf of {c.get('sub')}",
        actor=AGENT_ID, token=c)

    # ---- this agent's OWN AMP identity ----------------------------------
    gw = mcpgw.gateway_url()
    try:
        token = agentid.get_token(resource=mcpgw.gateway_resource())
    except agentid.AgentIDError as exc:
        hop(steps, "agent -> AMP IdP", "AMP", "DENY", str(exc))
        return {"status": "failed", "at": "agentid", "trace_id": trace_id,
                "steps": steps}
    hop(steps, "agent -> AMP IdP", "AMP", "ALLOW",
        "own client_credentials token; the asserted scopes are not carried over",
        actor=AGENT_ID, token=token_view(token))

    # ---- the confidential call, through the gateway ----------------------
    ctx = {"trace_id": trace_id, "actor": AGENT_ID, "runtime": RUNTIME,
           "user": c.get("sub"), "chain": c.get("delegation_chain", [])}
    out = mcpgw.call_tool(token, CONFIDENTIAL_TOOL,
                          {"payment_ref": req.payment_ref, "amount": req.amount},
                          trace_id=trace_id, context=ctx, url=gw)
    d = mcpgw.decision(out)
    hop(steps, "agent -> gateway -> mcp", "AMP",
        "ALLOW" if d["allowed"] else "DENY",
        f"{CONFIDENTIAL_TOOL}: {d['reason']}", actor=AGENT_ID,
        decided_by=d["by"], http_status=d["status"], endpoint=gw,
        result=d.get("result"))

    receipt = d.get("result") if d["allowed"] else None
    return {"status": "ok" if d["allowed"] else "denied",
            "agent": AGENT_ID, "trace_id": trace_id,
            "delegation_chain": c.get("delegation_chain", []),
            "acting_for": c.get("sub"),
            "payment_ref_used": req.payment_ref,
            "card_number_seen_by_agent": None,
            "receipt": receipt, "steps": steps}


@app.get("/whoami")
async def whoami():
    gw = mcpgw.gateway_url()
    info: Dict[str, Any] = {
        "agent": AGENT_ID, "runtime": RUNTIME,
        "agentid_configured": agentid.configured(),
        "scopes_requested": agentid.granted_scopes(),
        "mcp_gateway": mcpgw.endpoints(),
        "calls_mcp_directly": False,
        "trusted_delegators": TRUSTED_DELEGATORS,
    }
    if agentid.configured() and gw:
        try:
            info["token_claims"] = token_view(
                agentid.get_token(resource=mcpgw.gateway_resource()))
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
