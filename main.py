"""
Payments Agent (Agent B): the confidential-tier specialist.

Reached only through Agent A, with a token delegated on a user's behalf. Before
acting it checks that the token's `act` is Agent A. Then it exchanges that token
for its own, capped at its own grant, and handles the payment or refund with
vault references only: it never sees a card number.

The steps run as a LangGraph graph so Agent Manager's auto-instrumentation
traces each one, and the model's only job is a one-line receipt written from
masked data.
"""

from __future__ import annotations

import os
import uuid
from typing import Any, Dict, List, Optional, TypedDict

import httpx
import uvicorn
from fastapi import FastAPI, Header
from langgraph.graph import END, StateGraph
from pydantic import BaseModel

import httptrace  # noqa: F401  (wraps httpx first, so every outbound call is recorded)
import audit
import gateway
import identity
import llm

AGENT = os.getenv("AGENT_NAME", "demo3-payments")
TRUSTED_DELEGATOR = os.getenv("CONCIERGE_AGENT_ID", "")      # Agent A's AgentID subject
SCOPE = lambda a: f"{os.getenv('SCOPE_PREFIX', 'svc')}:{a}"   # noqa: E731
CONTROL = os.getenv("CONTROL_SERVICE_URL", "").rstrip("/")

app = FastAPI(title="Payments Agent", version="3.0")


class Settle(BaseModel):
    action: str                      # "pay" | "refund"
    application_id: str
    amount: float = 0.0
    reason: str = ""
    approval_ref: str = ""
    username: str = ""
    txn: str = ""


class S(TypedDict, total=False):
    req: Dict[str, Any]
    incoming: str
    trail: Any
    delegated: Dict[str, Any]
    profile: Dict[str, Any]
    outcome: Dict[str, Any]
    summary: str
    stop: bool


def _ctx(s: S) -> Dict[str, Any]:
    c = identity.claims(s["incoming"])
    return {"txn": s["trail"].txn, "actor": AGENT, "user": c.get("username") or s["req"].get("username"),
            "chain": ["user", "demo3-concierge", AGENT]}


def verify(s: S) -> S:
    c = identity.claims(s["incoming"])
    actor = (c.get("act") or {}).get("sub")
    if not actor:
        s["trail"].hop("verify delegation", "DENY", "token carries no act claim: not a delegation",
                       decided_by=AGENT, token=identity.view(s["incoming"]))
        return {"stop": True, "outcome": {"status": "denied", "reason": "not a delegated token"}}
    if TRUSTED_DELEGATOR and actor != TRUSTED_DELEGATOR:
        s["trail"].hop("verify delegation", "DENY", f"act={actor} is not the concierge agent",
                       decided_by=AGENT, token=identity.view(s["incoming"]))
        return {"stop": True, "outcome": {"status": "denied", "reason": "delegation not from the concierge agent"}}
    s["trail"].hop("verify delegation", "ALLOW", f"on behalf of {c.get('username') or c.get('sub')}, act = concierge",
                   decided_by=AGENT, token=identity.view(s["incoming"]))
    return {}


def delegate(s: S) -> S:
    need = [SCOPE("fees-pay") if s["req"]["action"] == "pay" else SCOPE("refund-request"), SCOPE("profile-read")]
    try:
        d = identity.delegate(s["incoming"], need)
    except identity.IdentityError as e:
        s["trail"].hop("token exchange (OBO)", "DENY", str(e), decided_by="ThunderID")
        return {"stop": True, "outcome": {"status": "denied", "reason": str(e)}}
    s["trail"].hop("token exchange (OBO)", "ALLOW" if d["granted"] else "DENY",
                   f"asked {d['requested']}, capped out {d['capped_out'] or 'nothing'}, granted {d['granted']}",
                   decided_by="ThunderID", token=d["view"], actor_token=d["actor_view"])
    return {"delegated": d}


def profile(s: S) -> S:
    user = identity.citizen(s["incoming"]) or s["req"].get("username") or ""
    r = gateway.call_tool(s["delegated"]["token"], "get_profile", {"username": user}, _ctx(s))
    s["trail"].hop("get_profile", "ALLOW" if r["allowed"] else "DENY", r["reason"][:160], decided_by=r["decided_by"],
                   result={k: v for k, v in (r.get("result") or {}).items() if k in ("payment_ref", "name")} if r["allowed"] else None)
    if not r["allowed"]:
        return {"stop": True, "outcome": {"status": "denied", "reason": r["reason"]}}
    return {"profile": r["result"]}


def execute(s: S) -> S:
    q, tok = s["req"], s["delegated"]["token"]
    if q["action"] == "pay":
        ref = s["profile"].get("payment_ref", "")
        r = gateway.call_tool(tok, "pay_fee", {"application_id": q["application_id"], "payment_ref": ref,
                                               "amount": q["amount"]}, _ctx(s))
        s["trail"].hop("pay_fee", "ALLOW" if r["allowed"] else "DENY",
                       f"paid with vault reference {ref}" if r["allowed"] else r["reason"][:200],
                       decided_by=r["decided_by"], result=r.get("result"))
        return {"outcome": {"status": "paid" if r["allowed"] else "denied", "receipt": r.get("result"),
                            "reason": r["reason"], "card_number_seen_by_agent": None}}
    r = gateway.call_tool(tok, "request_refund", {"application_id": q["application_id"], "amount": q["amount"],
                                                  "reason": q.get("reason", ""), "approval_ref": q.get("approval_ref", "")}, _ctx(s))
    res = r.get("result") or {}
    if r["allowed"] and res.get("status") == "HITL_REQUIRED":
        approval = _open_approval(s, res)
        s["trail"].hop("request_refund", "HITL", f"above {res.get('threshold')}: supervisor approval required",
                       decided_by="server policy", approval_id=approval.get("id"))
        return {"outcome": {"status": "hitl_required", "approval": approval, "request_id": res.get("request_id")}}
    s["trail"].hop("request_refund", "ALLOW" if r["allowed"] else "BLOCK" if r["decided_by"] == "server" else "DENY",
                   (f"refunded, approved by {res.get('approved_by')}" if r["allowed"] else r["reason"][:200]),
                   decided_by=r["decided_by"], result=res or None)
    return {"outcome": {"status": "refunded" if r["allowed"] else "blocked" if r["decided_by"] == "server" else "denied",
                        "result": res or None, "reason": r["reason"], "detail": r.get("detail")}}


def _open_approval(s: S, res: Dict[str, Any]) -> Dict[str, Any]:
    if not CONTROL:
        return {}
    try:
        r = httpx.post(f"{CONTROL}/approvals", timeout=10, headers={"User-Agent": identity.UA,
                       "Authorization": f"Bearer {identity.own_token()}"},
                       json={"txn": s["trail"].txn, "application_id": s["req"]["application_id"],
                             "amount": s["req"]["amount"], "request_id": res.get("request_id"),
                             "requested_by": identity.claims(s["incoming"]).get("username"), "agent": AGENT})
        return r.json()
    except (httpx.HTTPError, ValueError):
        return {}


def summarise(s: S) -> S:
    o = s.get("outcome") or {}
    text = f"{o.get('status', 'done')}"
    if llm.configured() and o.get("status") in ("paid", "refunded"):
        try:
            masked = o.get("receipt") or o.get("result")
            m = llm.chat_model().invoke([("system", "Write one short sentence confirming this transaction for the "
                                                    "citizen. Use only the fields given. Never invent numbers."),
                                         ("user", str(masked))])
            text = m.content
        except Exception as e:                     # the summary is a courtesy; the transaction already happened
            text = llm.guardrail_verdict(e) or f"{o.get('status')} (summary unavailable)"
    return {"summary": text}


def _route(s: S) -> str:
    return "summarise" if s.get("stop") else "next"


g = StateGraph(S)
for name, fn in (("verify", verify), ("delegate", delegate), ("profile", profile), ("execute", execute), ("summarise", summarise)):
    g.add_node(name, fn)
g.set_entry_point("verify")
g.add_conditional_edges("verify", _route, {"summarise": "summarise", "next": "delegate"})
g.add_conditional_edges("delegate", _route, {"summarise": "summarise", "next": "profile"})
g.add_conditional_edges("profile", _route, {"summarise": "summarise", "next": "execute"})
g.add_edge("execute", "summarise")
g.add_edge("summarise", END)
GRAPH = g.compile()


@app.post("/settle")
def settle(req: Settle, authorization: Optional[str] = Header(default=None),
           x_forwarded_authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    # The agent gateway validates the caller's token and forwards it as
    # X-Forwarded-Authorization (its jwt-auth default).
    raw = x_forwarded_authorization or authorization or ""
    token = raw[7:] if raw.lower().startswith("bearer ") else ""
    calls = httptrace.start(AGENT)
    trail = audit.Trail(req.txn or "txn-" + uuid.uuid4().hex[:12])
    if not token:
        trail.hop("verify delegation", "DENY", "no token presented", decided_by=AGENT)
        return {"status": "denied", "reason": "no token", "hops": trail.hops, "http": calls}
    out = GRAPH.invoke({"req": req.model_dump(), "incoming": token, "trail": trail},
                       config={"run_name": f"payments.{req.action}", "metadata": {"txn": trail.txn}})
    o = out.get("outcome") or {}
    return {**o, "summary": out.get("summary"), "agent": AGENT, "txn": trail.txn, "hops": trail.hops, "http": calls}


@app.get("/whoami")
def whoami() -> Dict[str, Any]:
    info: Dict[str, Any] = {"agent": AGENT, "agentid_configured": identity.configured(), "own_scopes": identity.OWN_SCOPES,
                            "trusted_delegator": TRUSTED_DELEGATOR, "llm_configured": llm.configured(),
                            "mcp_gateway": gateway.MCP_GATEWAY_URL}
    try:
        info["token"] = identity.view(identity.own_token())
    except identity.IdentityError as e:
        info["token_error"] = str(e)
    return info


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "agent": AGENT}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("AGENT_PORT", "8000")), log_level="info")
