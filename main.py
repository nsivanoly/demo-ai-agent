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
CONFIDENTIAL_TOOL = os.getenv("CONFIDENTIAL_TOOL", "configure_workflow")


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
            MCP_URL,
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
            "scopes_from_amp": agentid.granted_scopes()}
    if agentid.configured():
        try:
            info["token_claims"] = {
                k: v for k, v in claims_of(agentid.get_token()).items()
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
