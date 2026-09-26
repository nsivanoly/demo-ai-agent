"""
Concierge Agent (Agent A): the user-facing agent.

A LangGraph tool loop over the Services MCP tools, run on a user's behalf:

  * Before any tool runs, the agent checks that the USER's token carries the
    scopes that tool needs. If not, the graph pauses (LangGraph interrupt) and
    the portal shows the environment ThunderID's step-up consent screen. When
    the user allows, the graph resumes with the new token.
  * Its own tool calls use a delegated token (token exchange, act = this agent)
    capped at its own grant: reads and submissions.
  * Payments and refunds are outside its grant, so it delegates them to the
    Payments Agent under a token that names it as the actor.
  * Document checks run in a short-lived child agent with its own identity,
    created and deleted on demand.

The /scenario endpoints run the same code paths without the model, so the
headless checks are deterministic.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Annotated, Any, Dict, List, Optional, TypedDict

import httpx
import uvicorn
from fastapi import FastAPI, Header
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.types import Command, interrupt
from pydantic import BaseModel

import audit
import gateway
import identity
import llm

AGENT = os.getenv("AGENT_NAME", "demo3-concierge")
PREFIX = os.getenv("SCOPE_PREFIX", "svc")
PAYMENTS_URL = os.getenv("PAYMENTS_AGENT_URL", "").rstrip("/")
# Agents are sandboxed: a pod may not call another agent directly. The call goes through
# the agent gateway (which validates the delegated token), addressed in-cluster, with the
# public host name the gateway routes on.
AGENT_GATEWAY_HOST = os.getenv("AGENT_GATEWAY_HOST", "")
CONTROL = os.getenv("CONTROL_SERVICE_URL", "").rstrip("/")
SC = lambda a: f"{PREFIX}:{a}"   # noqa: E731

app = FastAPI(title="Concierge Agent", version="3.0")

# Per-conversation request context: the user's current token, the audit trail.
# The graph's own state lives in the checkpointer; tokens are kept out of it.
CTX: Dict[str, Dict[str, Any]] = {}

SYSTEM = (
    "You are the concierge for a public-services portal. Help the signed-in user with their profile, applications, "
    "fees and refunds by calling tools. Never ask for, repeat or invent card or ID numbers: payments use the stored "
    "vault reference automatically. If a tool reports it needs the user's consent or was refused, say so plainly. "
    "Be brief."
)

# ---------------------------------------------------------------------------
# Tools, and the scopes each needs from the USER's token
# ---------------------------------------------------------------------------

NEEDS = {
    "get_my_profile": [SC("profile-read")],
    "get_application": [SC("application-read")],
    "submit_application": [SC("application-submit")],
    "pay_fee": [SC("fees-pay"), SC("profile-read")],
    "request_refund": [SC("refund-request"), SC("profile-read")],
    "check_documents": [SC("application-read")],
}


def _mcp_ctx(c: Dict[str, Any]) -> Dict[str, Any]:
    return {"txn": c["trail"].txn, "actor": AGENT, "user": c["username"], "chain": ["user", AGENT]}


def _own_call(c: Dict[str, Any], tool_name: str, args: Dict[str, Any], scopes: List[str]) -> Dict[str, Any]:
    """Call a tool with a token delegated to THIS agent, capped at its own grant."""
    try:
        d = identity.delegate(c["token"], scopes)
    except identity.IdentityError as e:
        c["trail"].hop("token exchange (OBO)", "DENY", str(e), decided_by="ThunderID")
        return {"error": str(e)}
    c["trail"].hop("token exchange (OBO)", "ALLOW",
                   f"asked {scopes}, capped out {d['capped_out'] or 'nothing'}, granted {d['granted']}",
                   decided_by="ThunderID", token=d["view"])
    r = gateway.call_tool(d["token"], tool_name, args, _mcp_ctx(c))
    c["trail"].hop(tool_name, "ALLOW" if r["allowed"] else "DENY", r["reason"][:200], decided_by=r["decided_by"])
    return r["result"] if r["allowed"] else {"refused": r["reason"], "decided_by": r["decided_by"]}


def _to_payments(c: Dict[str, Any], body: Dict[str, Any]) -> Dict[str, Any]:
    """Delegate to Agent B. The token is exchanged for B's scopes WITHOUT capping at
    this agent's grant, because this agent will not use it: B caps it at B's grant."""
    need = NEEDS["pay_fee"] if body["action"] == "pay" else NEEDS["request_refund"]
    try:
        d = identity.delegate(c["token"], need, apply_cap=False)
    except identity.IdentityError as e:
        c["trail"].hop("token exchange (OBO) for the payments agent", "DENY", str(e), decided_by="ThunderID")
        return {"status": "denied", "reason": str(e)}
    c["trail"].hop("token exchange (OBO) for the payments agent", "ALLOW",
                   f"delegation for the payments agent: {d['granted']}", decided_by="ThunderID", token=d["view"])
    try:
        hdrs = {"Authorization": f"Bearer {d['token']}", "User-Agent": identity.UA}
        if AGENT_GATEWAY_HOST:
            hdrs["Host"] = AGENT_GATEWAY_HOST
        r = httpx.post(f"{PAYMENTS_URL}/settle", timeout=90, headers=hdrs,
                       json={**body, "txn": c["trail"].txn, "username": c["username"]})
        out = r.json()
    except (httpx.HTTPError, ValueError) as e:
        c["trail"].hop("call payments agent", "DENY", f"payments agent unreachable: {e}", decided_by="network")
        return {"status": "failed", "reason": str(e)}
    c["trail"].hops.extend(out.get("hops") or [])
    return {k: v for k, v in out.items() if k != "hops"}


def _child(c: Dict[str, Any], application_id: str, scopes: List[str], try_tools: List[str]) -> Dict[str, Any]:
    """Spawn a child agent with its own short-lived identity, use it, terminate it, prove it is unusable."""
    auth = {"Authorization": f"Bearer {identity.own_token()}", "User-Agent": identity.UA}
    try:
        r = httpx.post(f"{CONTROL}/children", timeout=30, headers=auth,
                       json={"purpose": "document check", "scopes": scopes, "txn": c["trail"].txn})
        child = r.json()
    except (httpx.HTTPError, ValueError) as e:
        c["trail"].hop("spawn child", "DENY", f"control service unreachable: {e}")
        return {"status": "failed", "reason": str(e)}
    if r.status_code >= 400:
        c["trail"].hop("spawn child", "DENY", child.get("reason", r.text[:200]), decided_by="control service (broker)")
        return {"status": "refused", "reason": child.get("reason")}
    c["trail"].hop("spawn child", "ALLOW", f"child {child['name']} with {child['scopes']}, token life {child['token_seconds']}s",
                   decided_by="ThunderID", child=child["name"], owner=child.get("owner"))
    results: Dict[str, Any] = {"child": child["name"]}
    try:
        tok_r = httpx.post(identity.TOKEN_ENDPOINT, auth=(child["client_id"], child["client_secret"]), timeout=15,
                           data={"grant_type": "client_credentials", "scope": " ".join(scopes + [SC("fees-pay")]),
                                 "resource": identity.MCP_RESOURCE}, headers={"User-Agent": identity.UA})
        ctok = tok_r.json().get("access_token", "")
        c["trail"].hop("child: own token", "ALLOW" if ctok else "DENY",
                       f"asked {scopes + [SC('fees-pay')]}, granted {identity.scopes_of(ctok)}",
                       decided_by="ThunderID", token=identity.view(ctok) if ctok else None)
        for t in try_tools:
            args = {"application_id": application_id} if t == "get_application_status" else \
                   {"application_id": application_id, "payment_ref": "tok_card_9931", "amount": 1}
            rr = gateway.call_tool(ctok, t, args, {**_mcp_ctx(c), "actor": child["name"]})
            c["trail"].hop(f"child: {t}", "ALLOW" if rr["allowed"] else "DENY", rr["reason"][:160], decided_by=rr["decided_by"])
            results[t] = rr["result"] if rr["allowed"] else {"refused": rr["reason"]}
    finally:
        try:
            httpx.delete(f"{CONTROL}/children/{child['id']}", headers=auth, timeout=15)
        except httpx.HTTPError:
            pass
        after = httpx.post(identity.TOKEN_ENDPOINT, auth=(child["client_id"], child["client_secret"]), timeout=15,
                           data={"grant_type": "client_credentials", "resource": identity.MCP_RESOURCE},
                           headers={"User-Agent": identity.UA})
        c["trail"].hop("terminate child", "ALLOW" if after.status_code != 200 else "DENY",
                       f"identity deleted; a new mint now returns {after.status_code} "
                       f"{(after.json() if after.headers.get('content-type','').startswith('application/json') else {}).get('error', '')}",
                       decided_by="ThunderID")
        results["after_termination_mint"] = after.status_code
    return results


def run_tool(name: str, args: Dict[str, Any], c: Dict[str, Any]) -> Any:
    if name == "get_my_profile":
        return _own_call(c, "get_profile", {"username": c["username"]}, NEEDS[name])
    if name == "get_application":
        return _own_call(c, "get_application_status", {"application_id": args["application_id"]}, NEEDS[name])
    if name == "submit_application":
        return _own_call(c, "submit_application", {"service": args["service"], "details": args.get("details", "")}, NEEDS[name])
    if name == "pay_fee":
        app_ = _own_call(c, "get_application_status", {"application_id": args["application_id"]}, [SC("application-read")])
        amount = float((app_ or {}).get("fee_due") or 0)
        if amount <= 0:
            return {"status": "nothing to pay", "application": app_}
        return _to_payments(c, {"action": "pay", "application_id": args["application_id"], "amount": amount})
    if name == "request_refund":
        return _to_payments(c, {"action": "refund", "application_id": args["application_id"],
                                "amount": float(args["amount"]), "reason": args.get("reason", ""),
                                "approval_ref": args.get("approval_ref", "")})
    if name == "check_documents":
        return _child(c, args["application_id"], [SC("application-read")], ["get_application_status"])
    return {"error": f"unknown tool {name}"}


@tool
def get_my_profile() -> str:
    """Get the signed-in user's profile (sensitive values are masked)."""
    return ""


@tool
def get_application(application_id: str) -> str:
    """Get the status of a service application, e.g. APP-5001."""
    return ""


@tool
def submit_application(service: str, details: str = "") -> str:
    """Submit a new service application."""
    return ""


@tool
def pay_fee(application_id: str) -> str:
    """Pay the outstanding fee on an application using the user's stored payment method."""
    return ""


@tool
def request_refund(application_id: str, amount: float, reason: str = "") -> str:
    """Request a refund of an overpayment on an application."""
    return ""


@tool
def check_documents(application_id: str) -> str:
    """Check the documents on an application (runs in a short-lived child agent)."""
    return ""


TOOLS = [get_my_profile, get_application, submit_application, pay_fee, request_refund, check_documents]

# ---------------------------------------------------------------------------
# The graph
# ---------------------------------------------------------------------------


class S(TypedDict):
    messages: Annotated[list, add_messages]


def agent_node(state: S, config) -> Dict[str, Any]:
    model = llm.chat_model().bind_tools(TOOLS)
    msg = model.invoke([SystemMessage(SYSTEM)] + state["messages"])
    return {"messages": [msg]}


def tools_node(state: S, config) -> Dict[str, Any]:
    tid = config["configurable"]["thread_id"]
    calls = state["messages"][-1].tool_calls
    # Consent is checked for EVERY call before ANY runs: when the graph resumes after
    # an interrupt this node starts again from the top, so nothing may have run yet.
    for _ in range(2):
        have = set(identity.scopes_of(CTX[tid]["token"]))
        missing = sorted({s for call in calls for s in NEEDS.get(call["name"], [])} - have)
        if not missing:
            break
        CTX[tid]["trail"].hop("consent check", "CONSENT", f"the user's token lacks {missing}", decided_by=AGENT)
        answer = interrupt({"type": "consent_required", "scopes": missing,
                            "tools": [call["name"] for call in calls]})
        if not (answer or {}).get("approved"):
            return {"messages": [ToolMessage(content=json.dumps({"refused": "the user did not consent"}),
                                             tool_call_id=call["id"]) for call in calls]}
    out = []
    for call in calls:
        missing = [s for s in NEEDS.get(call["name"], []) if s not in identity.scopes_of(CTX[tid]["token"])]
        result = ({"refused": f"the user did not consent to {missing}"} if missing
                  else run_tool(call["name"], call["args"], CTX[tid]))
        out.append(ToolMessage(content=json.dumps(result, default=str)[:4000], tool_call_id=call["id"]))
    return {"messages": out}


def _next(state: S) -> str:
    last = state["messages"][-1]
    return "tools" if isinstance(last, AIMessage) and last.tool_calls else END


g = StateGraph(S)
g.add_node("agent", agent_node)
g.add_node("tools", tools_node)
g.set_entry_point("agent")
g.add_conditional_edges("agent", _next, {"tools": "tools", END: END})
g.add_edge("tools", "agent")
GRAPH = g.compile(checkpointer=MemorySaver())

# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class Chat(BaseModel):
    message: str = ""
    thread_id: str = ""
    txn: str = ""


class Resume(BaseModel):
    thread_id: str
    approved: bool = True


def _bearer(h: Optional[str]) -> str:
    return h[7:] if (h or "").lower().startswith("bearer ") else ""


def _caller(forwarded: Optional[str], authorization: Optional[str]) -> str:
    """The caller's token. The agent gateway validates it and forwards it as
    X-Forwarded-Authorization (its jwt-auth default); Authorization is the fallback
    for a call that did not come through the gateway."""
    return _bearer(forwarded) or _bearer(authorization)


def _context(tid: str, token: str, txn: str) -> Dict[str, Any]:
    c = identity.claims(token)
    ctx = CTX.get(tid) or {"trail": audit.Trail(txn or "txn-" + uuid.uuid4().hex[:12])}
    ctx.update(token=token, username=c.get("username") or c.get("sub"))
    CTX[tid] = ctx
    return ctx


def _reply(tid: str, result: Dict[str, Any]) -> Dict[str, Any]:
    c = CTX[tid]
    if result.get("__interrupt__"):
        ask = result["__interrupt__"][0].value
        return {"status": "consent_required", "thread_id": tid, "txn": c["trail"].txn, **ask, "hops": c["trail"].hops}
    last = next((m for m in reversed(result["messages"]) if isinstance(m, AIMessage)), None)
    return {"status": "ok", "thread_id": tid, "txn": c["trail"].txn, "answer": last.content if last else "",
            "hops": c["trail"].hops}


def _guarded(tid: str, fn) -> Dict[str, Any]:
    try:
        return _reply(tid, fn())
    except Exception as e:
        verdict = llm.guardrail_verdict(e)
        if not verdict:
            raise
        CTX[tid]["trail"].hop("LLM call", "BLOCK", verdict, decided_by="Agent Manager LLM gateway")
        return {"status": "blocked", "thread_id": tid, "txn": CTX[tid]["trail"].txn, "answer": verdict,
                "hops": CTX[tid]["trail"].hops}


@app.post("/chat")
def chat(req: Chat, authorization: Optional[str] = Header(default=None),
         x_forwarded_authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    tid = req.thread_id or "t-" + uuid.uuid4().hex[:10]
    c = _context(tid, _caller(x_forwarded_authorization, authorization), req.txn)
    c["trail"].hop("user → agent", "ALLOW", f"signed in as {c['username']}", decided_by="Agent Manager agent gateway",
                   token=identity.view(c["token"]))
    cfg = {"configurable": {"thread_id": tid}, "run_name": "concierge.chat", "metadata": {"txn": c["trail"].txn}}
    return _guarded(tid, lambda: GRAPH.invoke({"messages": [HumanMessage(req.message)]}, cfg))


@app.post("/chat/resume")
def resume(req: Resume, authorization: Optional[str] = Header(default=None),
         x_forwarded_authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    c = _context(req.thread_id, _caller(x_forwarded_authorization, authorization), "")
    c["trail"].hop("step-up consent", "ALLOW" if req.approved else "DENY",
                   f"user token now carries {identity.scopes_of(c['token'])}", decided_by="ThunderID consent",
                   token=identity.view(c["token"]))
    cfg = {"configurable": {"thread_id": req.thread_id}, "run_name": "concierge.resume"}
    return _guarded(req.thread_id, lambda: GRAPH.invoke(Command(resume={"approved": req.approved}), cfg))


# --- deterministic paths for the headless scenario checks -------------------

class Scenario(BaseModel):
    application_id: str = "APP-5001"
    amount: float = 0.0
    approval_ref: str = ""
    scopes: List[str] = []
    try_tools: List[str] = ["get_application_status", "pay_fee"]
    txn: str = ""


def _scenario_ctx(token: str, txn: str) -> Dict[str, Any]:
    tid = "s-" + uuid.uuid4().hex[:10]
    return _context(tid, token, txn)


@app.post("/scenario/{name}")
def scenario(name: str, req: Scenario, authorization: Optional[str] = Header(default=None),
         x_forwarded_authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    c = _scenario_ctx(_caller(x_forwarded_authorization, authorization), req.txn)
    c["trail"].hop("user → agent", "ALLOW", f"signed in as {c['username']}", decided_by="Agent Manager agent gateway",
                   token=identity.view(c["token"]))
    if name == "read":
        out = run_tool("get_application", {"application_id": req.application_id}, c)
    elif name == "pay":
        out = run_tool("pay_fee", {"application_id": req.application_id}, c)
    elif name == "refund":
        out = run_tool("request_refund", {"application_id": req.application_id, "amount": req.amount,
                                          "approval_ref": req.approval_ref}, c)
    elif name == "child":
        out = _child(c, req.application_id, req.scopes or [SC("application-read")], req.try_tools)
    elif name == "own-token-direct":
        # What this agent could do with ONLY its own AgentID token (no user), for the lifecycle scenario.
        tok = identity.own_token()
        r = gateway.call_tool(tok, req.try_tools[0], {"application_id": req.application_id, "payment_ref": "tok_card_9931",
                                                      "amount": 1}, _mcp_ctx(c))
        c["trail"].hop(f"own token: {req.try_tools[0]}", "ALLOW" if r["allowed"] else "DENY", r["reason"][:160],
                       decided_by=r["decided_by"], token=identity.view(tok))
        out = {"allowed": r["allowed"], "status": r["status"]}
    else:
        out = {"error": f"unknown scenario {name}"}
    return {"scenario": name, "result": out, "txn": c["trail"].txn, "hops": c["trail"].hops}


@app.get("/whoami")
def whoami() -> Dict[str, Any]:
    info: Dict[str, Any] = {"agent": AGENT, "agentid_configured": identity.configured(), "own_scopes": identity.OWN_SCOPES,
                            "llm_configured": llm.configured(), "payments_agent": PAYMENTS_URL,
                            "mcp_gateway": gateway.MCP_GATEWAY_URL, "control_service": CONTROL}
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
