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
BROKER_URL = os.getenv("BROKER_URL", "http://host.k3d.internal:8890")
PAYMENTS_URL = os.getenv("PAYMENTS_AGENT_URL", "http://host.k3d.internal:8894")
LOW_TOOL = os.getenv("LOW_TOOL", "process_order")
CONFIDENTIAL_SCOPE = os.getenv("CONFIDENTIAL_SCOPE", "")


def new_trace() -> str:
    return "txn-" + uuid.uuid4().hex[:16]


async def call_tool(client: httpx.AsyncClient, token: str, trace_id: str,
                    tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
    r = await client.post(MCP_URL,
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
        token = agentid.get_token()
    except agentid.AgentIDError as exc:
        return {"trace_id": trace_id, "status": "failed", "at": "agentid",
                "detail": str(exc)}
    steps.append({"hop": "agentid", "action": "AgentID token minted",
                  "scopes": agentid.granted_scopes(), "credential": "AMP"})

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
            "scopes_from_amp": agentid.granted_scopes()}
    if agentid.configured():
        try:
            import base64, json
            p = agentid.get_token().split(".")[1]
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
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")), log_level="warning")
