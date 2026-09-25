"""
Concierge Agent -- the user-facing orchestrator.

Runs as a platform-hosted WSO2 Agent Manager agent. Its identity is a real
AgentID: AMP injects the client credentials, the agent exchanges them for an
access token, and AMP filters the scopes in that token against the roles the
agent has been assigned.

It holds read scopes and nothing more. Anything confidential it must get done
by the payments agent, which is the point: the delegation is forced by the
authorization model, not staged.

The chain it drives, per request:

    user token (OIDC, verified against the issuer's JWKS)
      -> AgentID token, bound to the MCP gateway as its RFC 8707 resource
      -> gateway -> MCP server            (work this agent may do itself)
      -> OBO assertion for the payments agent
      -> payments agent
      -> its own AgentID token -> gateway -> MCP server

Every hop is recorded with the credential it used and the decision that was
made, so the response is the audit record for the whole transaction.
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, List, Optional

import httpx
import uvicorn
from fastapi import FastAPI, Header
from pydantic import BaseModel

import agentid
import mcpgw
import obo
import tracing
import userauth

app = FastAPI(title="Concierge Agent", version="2.0.0")

AGENT_ID = os.getenv("AGENT_NAME", "demo2-concierge-agent")
RUNTIME = os.getenv("AGENT_RUNTIME", "runtime-a")
PAYMENTS_AGENT = os.getenv("PAYMENTS_AGENT_NAME", "demo2-payments-agent")
PAYMENTS_URL = os.getenv("PAYMENTS_AGENT_URL", "")
# Several plausible in-cluster addresses, tried in order. The service name and
# port are not discoverable from inside the agent, and the published endpoint
# sits behind an API key this agent has no way to obtain -- so the honest thing
# is to try the likely ones and record the failure if none of them answer.
PAYMENTS_CANDIDATES = [u.strip() for u in os.getenv(
    "PAYMENTS_AGENT_URLS",
    "http://demo2-payments-agent:8000,"
    "http://demo2-payments-agent,"
    "http://demo2-payments-agent-service:8000").split(",") if u.strip()]
LOW_TOOL = os.getenv("LOW_TOOL", "get_order")
CONFIDENTIAL_SCOPE = os.getenv("CONFIDENTIAL_SCOPE", "")
REQUIRE_USER_TOKEN = os.getenv("REQUIRE_USER_TOKEN", "true").lower() != "false"

_payments_base: Optional[str] = None


def new_trace() -> str:
    return "txn-" + uuid.uuid4().hex[:16]


def hop(steps: List[Dict[str, Any]], name: str, credential: str,
        decision: str, detail: str, **extra: Any) -> Dict[str, Any]:
    row = {"seq": len(steps) + 1, "hop": name, "credential": credential,
           "decision": decision, "detail": detail,
           "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    row.update(extra)
    steps.append(row)
    return row


def token_view(tok: str) -> Dict[str, Any]:
    """The parts of a token worth showing at a hop."""
    c = agentid.claims(tok)
    return {k: c.get(k) for k in ("iss", "sub", "aud", "scope", "act",
                                  "delegation_chain", "exp") if c.get(k) is not None}


async def payments_base(client: httpx.AsyncClient) -> str:
    """Where the payments agent answers.

    Prefer the in-cluster service, which is the hop a deployed agent would
    really take; fall back to the endpoint AMP publishes. Probed once.
    """
    global _payments_base
    if _payments_base is not None:
        return _payments_base
    for candidate in PAYMENTS_CANDIDATES + ([PAYMENTS_URL] if PAYMENTS_URL else []):
        if not candidate:
            continue
        try:
            r = await client.get(f"{candidate.rstrip('/')}/health", timeout=5)
            if r.status_code < 400:
                _payments_base = candidate.rstrip("/")
                return _payments_base
        except Exception:
            continue
    _payments_base = (PAYMENTS_CANDIDATES[0] if PAYMENTS_CANDIDATES
                      else PAYMENTS_URL).rstrip("/")
    return _payments_base


class TaskRequest(BaseModel):
    intent: str = "pay"                # "read" stops after the agent's own work
    order_id: str = "ORD-77001"
    customer_id: str = "CUST-1001"
    amount: float = 249.00
    payment_ref: str = "tok_card_9931"
    trace_id: Optional[str] = None
    # Scenario levers. Each one changes what the flow does, so a scenario is a
    # variation of this single chain rather than a script of its own.
    request_scopes: Optional[List[str]] = None   # ask to delegate specific scopes
    skip_delegation: bool = False                # try the confidential tool itself
    obo_ttl: int = 120


def _bearer(value: Optional[str]) -> str:
    v = value or ""
    return v[7:].strip() if v.lower().startswith("bearer ") else ""


@app.post("/task")
@tracing.agent_entry("concierge_task", agent=AGENT_ID, runtime=RUNTIME)
async def task(req: TaskRequest,
               authorization: Optional[str] = Header(default=None),
               x_user_authorization: Optional[str] = Header(default=None)):
    """User -> this agent -> payments agent -> gateway -> MCP.

    The user's token can arrive two ways, and both are verified here.

      Authorization          when the Agent Manager gateway has an identity
                             provider registered for the token's issuer, it
                             validates the token and -- with forwardToken on --
                             passes it straight through.
      X-User-Authorization   when it does not. The gateway only trusts issuers
                             in its key manager list; on this build a custom
                             provider registered through the API is stored and
                             listed for the environment but never reaches that
                             list, so a token from the platform identity
                             provider is refused at the edge. The caller then
                             authenticates to the gateway with its own client
                             credential and carries the user's token here,
                             where this agent verifies its signature against
                             the issuer's key set before acting on it.

    Either way nothing is taken on trust: whichever header carries it, the
    token is cryptographically verified before the agent does anything on the
    user's behalf.
    """
    trace_id = req.trace_id or new_trace()
    steps: List[Dict[str, Any]] = []
    gw = mcpgw.gateway_url()

    # ---- hop 1: the user ------------------------------------------------
    bearer = _bearer(x_user_authorization) or _bearer(authorization)
    via = ("X-User-Authorization" if _bearer(x_user_authorization)
           else "Authorization" if _bearer(authorization) else "")
    tracing.set_attributes(trace_id=trace_id, agent=AGENT_ID, runtime=RUNTIME,
                           user_token_via=via or "none")
    if not bearer:
        if REQUIRE_USER_TOKEN:
            hop(steps, "user -> agent", "USER", "DENY",
                "no user token presented on the request")
            return {"trace_id": trace_id, "status": "denied", "at": "user",
                    "steps": steps}
        user = {"username": "anonymous", "sub": "anonymous"}
        hop(steps, "user -> agent", "USER", "ALLOW",
            "running without a user token (REQUIRE_USER_TOKEN=false)")
    else:
        async with tracing.hop("verify_user_token", trace_id=trace_id):
            try:
                userauth.verify(bearer, issuer=os.getenv("USER_TOKEN_ISSUER") or None)
                user = userauth.identity(bearer)
                hop(steps, "user -> agent", "USER", "ALLOW",
                    f"user token verified against {user['issuer']} "
                    f"(presented in {via})",
                    actor=user["username"], token=userauth.identity(bearer))
                tracing.record_decision("ALLOW", "agent",
                                        "user token signature verified",
                                        user=user["username"],
                                        issuer=user["issuer"])
            except userauth.UserAuthError as exc:
                user = userauth.identity(bearer)
                hop(steps, "user -> agent", "USER", "DENY", str(exc),
                    actor=user.get("username"))
                tracing.record_decision("DENY", "agent", str(exc))
                return {"trace_id": trace_id, "status": "denied", "at": "user",
                        "steps": steps}

    # ---- hop 2: this agent's own AMP identity ---------------------------
    async with tracing.hop("mint_agentid_token", trace_id=trace_id):
        try:
            token = agentid.get_token(resource=mcpgw.gateway_resource())
        except agentid.AgentIDError as exc:
            hop(steps, "agent -> AMP IdP", "AMP", "DENY", str(exc))
            tracing.record_decision("DENY", "amp-idp", str(exc))
            return {"trace_id": trace_id, "status": "failed", "at": "agentid",
                    "steps": steps}
        my_scopes = (agentid.claims(token).get("scope") or "").split()
        hop(steps, "agent -> AMP IdP", "AMP", "ALLOW",
            "client_credentials; AMP filtered the scopes against assigned roles",
            actor=AGENT_ID, token=token_view(token))
        tracing.record_decision("ALLOW", "amp-idp",
                                "scopes filtered against assigned roles",
                                granted_scopes=my_scopes,
                                resource=mcpgw.gateway_resource())

    async with httpx.AsyncClient(timeout=60) as client:
        ctx = {"trace_id": trace_id, "actor": AGENT_ID, "runtime": RUNTIME,
               "user": user.get("username"), "chain": [user.get("username"), AGENT_ID]}

        # ---- hop 3: work this agent is entitled to do itself -------------
        async with tracing.tool_call(LOW_TOOL, trace_id=trace_id, tool=LOW_TOOL,
                                     endpoint=gw, actor=AGENT_ID):
            out = mcpgw.call_tool(token, LOW_TOOL, {"order_id": req.order_id},
                                  trace_id=trace_id, context=ctx, url=gw)
            d = mcpgw.decision(out)
            hop(steps, "agent -> gateway -> mcp", "AMP",
                "ALLOW" if d["allowed"] else "DENY",
                f"{LOW_TOOL}: {d['reason']}", decided_by=d["by"],
                http_status=d["status"], result=d.get("result"), endpoint=gw)
            tracing.record_decision("ALLOW" if d["allowed"] else "DENY",
                                    d["by"], d["reason"],
                                    http_status=d["status"])

        if req.skip_delegation:
            # Deliberately attempt the confidential tool with this agent's own
            # token. The gateway is what refuses it.
            conf = os.getenv("CONFIDENTIAL_TOOL", "charge_card")
            async with tracing.tool_call(conf, trace_id=trace_id, tool=conf,
                                         endpoint=gw, actor=AGENT_ID,
                                         note="attempted without delegation"):
                out = mcpgw.call_tool(token, conf,
                                      {"payment_ref": req.payment_ref,
                                       "amount": req.amount},
                                      trace_id=trace_id, context=ctx, url=gw)
                d = mcpgw.decision(out)
                hop(steps, "agent -> gateway -> mcp", "AMP",
                    "ALLOW" if d["allowed"] else "DENY",
                    f"{conf}: {d['reason']}", decided_by=d["by"],
                    http_status=d["status"], endpoint=gw)
                tracing.record_decision("ALLOW" if d["allowed"] else "DENY",
                                        d["by"], d["reason"],
                                        http_status=d["status"],
                                        scope_required=CONFIDENTIAL_SCOPE)
            return {"trace_id": trace_id,
                    "status": "ok" if d["allowed"] else "denied",
                    "agent": AGENT_ID, "user": user, "steps": steps}

        if req.intent != "pay":
            return {"trace_id": trace_id, "status": "ok", "agent": AGENT_ID,
                    "user": user, "steps": steps}

        # ---- hop 4: on-behalf-of exchange --------------------------------
        want = req.request_scopes or [CONFIDENTIAL_SCOPE]
        want = [s for s in want if s]
        chain = [user.get("username", "user"), AGENT_ID, PAYMENTS_AGENT]
        async with tracing.hop("obo_exchange", trace_id=trace_id,
                               audience=PAYMENTS_AGENT, requested_scope=want):
          try:
            assertion = obo.issue(
                actor=AGENT_ID, subject=user.get("username", "user"),
                audience=PAYMENTS_AGENT, scope=want, delegation_chain=chain,
                trace_id=trace_id, ttl_seconds=req.obo_ttl,
                # Deliberately NOT actor_scopes=my_scopes: the concierge is
                # supposed to be able to ask the payments agent for something
                # it cannot do itself -- that is delegation, not escalation.
                # Escalation is constrained on the sub-agent path instead,
                # where the child must stay within the parent's own grant.
                user_sub=user.get("sub", ""), runtime=RUNTIME)
            hop(steps, "agent -> obo exchange", "DEMO", "ALLOW",
                f"assertion minted for {PAYMENTS_AGENT}, {req.obo_ttl}s",
                actor=AGENT_ID, token=obo.claims(assertion))
            tracing.record_decision("ALLOW", "agent",
                                    f"on-behalf-of assertion for {PAYMENTS_AGENT}",
                                    delegation_chain=chain, ttl_seconds=req.obo_ttl,
                                    credential_kind="DEMO")
          except obo.OBOError as exc:
            hop(steps, "agent -> obo exchange", "DEMO", "DENY", str(exc),
                actor=AGENT_ID)
            tracing.record_decision("DENY", "agent", str(exc))
            return {"trace_id": trace_id, "status": "denied", "at": "obo",
                    "agent": AGENT_ID, "user": user, "steps": steps}

        # ---- hop 5: agent -> agent ---------------------------------------
        base = await payments_base(client)
        async with tracing.hop("call_payments_agent", trace_id=trace_id,
                               peer=PAYMENTS_AGENT, endpoint=base):
          try:
            r = await client.post(
                f"{base}/settle",
                json={"amount": req.amount, "payment_ref": req.payment_ref,
                      "trace_id": trace_id},
                headers={"Authorization": f"Bearer {assertion}"})
            body = r.json()
          except Exception as exc:
            hop(steps, "agent -> agent", "DEMO", "DENY",
                f"payments agent unreachable at {base}: {exc}")
            tracing.record_decision("DENY", "agent",
                                    f"payments agent unreachable: {exc}")
            return {"trace_id": trace_id, "status": "failed", "at": "agent-to-agent",
                    "agent": AGENT_ID, "user": user, "steps": steps}

          hop(steps, "agent -> agent", "DEMO",
              "ALLOW" if r.status_code < 400 else "DENY",
              f"POST {base}/settle -> {r.status_code}", actor=AGENT_ID,
              peer=PAYMENTS_AGENT)
          tracing.record_decision("ALLOW" if r.status_code < 400 else "DENY",
                                  "payments-agent",
                                  f"settle -> HTTP {r.status_code}",
                                  http_status=r.status_code)
        steps.extend(body.get("steps", []))
        for i, s in enumerate(steps, 1):
            s["seq"] = i

    ok = body.get("status") == "ok"
    return {"trace_id": trace_id, "status": "ok" if ok else "denied",
            "agent": AGENT_ID, "user": user, "receipt": body.get("receipt"),
            "delegation_chain": chain, "steps": steps}


class SpawnRequest(BaseModel):
    purpose: str = "summarise one order"
    scopes: List[str] = []
    ttl_seconds: int = 8
    trace_id: Optional[str] = None


@app.post("/spawn")
async def spawn(req: SpawnRequest,
                authorization: Optional[str] = Header(default=None)):
    """Issue a short-lived child identity with a subset of this agent's scopes.

    AMP v1.0.0 has no parent/child agent concept, no TTL field and no spawn
    API, so the child credential is demo-minted. What is NOT demo-minted is the
    ceiling: the parent's scopes come from the AgentID token AMP just issued,
    so the child can never be given something the parent does not actually
    hold.
    """
    trace_id = req.trace_id or new_trace()
    steps: List[Dict[str, Any]] = []
    gw = mcpgw.gateway_url()
    try:
        parent_token = agentid.get_token(resource=mcpgw.gateway_resource())
    except agentid.AgentIDError as exc:
        return {"trace_id": trace_id, "status": "failed", "detail": str(exc)}

    parent_scopes = (agentid.claims(parent_token).get("scope") or "").split()
    hop(steps, "agent -> AMP IdP", "AMP", "ALLOW",
        "parent scopes read from the AgentID token", actor=AGENT_ID,
        token=token_view(parent_token))

    child_id = f"{AGENT_ID}/child-{uuid.uuid4().hex[:8]}"
    want = req.scopes or parent_scopes[:1]
    try:
        assertion = obo.issue(
            actor=AGENT_ID, subject=child_id, audience=child_id,
            scope=want, delegation_chain=[AGENT_ID, child_id],
            trace_id=trace_id, ttl_seconds=req.ttl_seconds, kind="subagent",
            actor_scopes=parent_scopes,      # the escalation check lives here
            parent_agent=AGENT_ID, purpose=req.purpose, runtime=RUNTIME)
    except obo.OBOError as exc:
        hop(steps, "agent -> subagent issue", "DEMO", "DENY", str(exc),
            actor=AGENT_ID, requested=want, parent_scopes=parent_scopes)
        return {"trace_id": trace_id, "status": "denied", "reason": str(exc),
                "parent_scopes": parent_scopes, "requested": want, "steps": steps}

    hop(steps, "agent -> subagent issue", "DEMO", "ALLOW",
        f"child identity issued, {req.ttl_seconds}s", actor=AGENT_ID,
        token=obo.claims(assertion))
    return {"trace_id": trace_id, "status": "ok", "subagent_id": child_id,
            "parent": AGENT_ID, "parent_scopes": parent_scopes,
            "scopes": want, "expires_in": req.ttl_seconds,
            "assertion": assertion, "steps": steps}


class ChildCallRequest(BaseModel):
    assertion: str
    tool: str = "get_order"
    arguments: Dict[str, Any] = {}
    trace_id: Optional[str] = None


@app.post("/child-call")
async def child_call(req: ChildCallRequest):
    """Let a child identity act, within the scopes its assertion carries.

    The child has no AgentID of its own -- AMP does not issue one -- so the
    parent presents its own AMP token to the gateway and constrains the call to
    the child's scopes first. The refusal below is the child's TTL and scope
    set being enforced; the gateway independently enforces the parent's.
    """
    trace_id = req.trace_id or new_trace()
    steps: List[Dict[str, Any]] = []
    try:
        c = obo.verify(req.assertion, audience=obo.claims(req.assertion).get("aud", ""))
    except obo.OBOError as exc:
        hop(steps, "subagent -> agent", "DEMO", "DENY", str(exc))
        return {"trace_id": trace_id, "status": "denied", "reason": str(exc),
                "steps": steps}

    gw = mcpgw.gateway_url()
    parent_token = agentid.get_token(resource=mcpgw.gateway_resource())
    child_scopes = (c.get("scope") or "").split()
    needed = os.getenv("TOOL_SCOPE_" + req.tool, "")
    if needed and needed not in child_scopes:
        hop(steps, "subagent -> agent", "DEMO", "DENY",
            f"{req.tool} needs {needed}, which the child was not given",
            child_scopes=child_scopes)
        return {"trace_id": trace_id, "status": "denied",
                "reason": f"{req.tool} is outside the child's grant", "steps": steps}

    ctx = {"trace_id": trace_id, "actor": c.get("sub"), "runtime": RUNTIME,
           "chain": c.get("delegation_chain", [])}
    out = mcpgw.call_tool(parent_token, req.tool, req.arguments,
                          trace_id=trace_id, context=ctx, url=gw)
    d = mcpgw.decision(out)
    hop(steps, "subagent -> gateway -> mcp", "AMP+DEMO",
        "ALLOW" if d["allowed"] else "DENY", f"{req.tool}: {d['reason']}",
        actor=c.get("sub"), decided_by=d["by"], http_status=d["status"],
        result=d.get("result"))
    return {"trace_id": trace_id, "status": "ok" if d["allowed"] else "denied",
            "steps": steps}


@app.get("/whoami")
async def whoami():
    """What this agent's real AMP identity permits, and where it calls."""
    gw = mcpgw.gateway_url()
    info: Dict[str, Any] = {
        "agent": AGENT_ID, "runtime": RUNTIME,
        "agentid_configured": agentid.configured(),
        "scopes_requested": agentid.granted_scopes(),
        "mcp_gateway": mcpgw.endpoints(),
        "calls_mcp_directly": False,
        "tracing": tracing.status(),
        "payments_agent": {"name": PAYMENTS_AGENT,
                           "candidates": PAYMENTS_CANDIDATES,
                           "published": PAYMENTS_URL},
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
