"""
Payments Agent -- the confidential-tier specialist, an A2A agent.

Runs as a platform-hosted WSO2 Agent Manager agent of the A2A type: it serves its own Agent
Card and speaks A2A, and Agent Manager's gateway publishes it under /<agent>/rpc (JSON-RPC)
and /<agent>/rest (HTTP+JSON), with OAuth in front. The concierge reaches it there, never a
user directly.

What it accepts is a REAL delegation: a token the environment identity provider issued by
token exchange (RFC 8693), saying "the concierge, acting for this user" -- sub = the user,
act = the concierge, client_id = the concierge's client. The gateway has already checked the
signature, issuer and expiry; this agent checks that the delegation came from a delegator it
trusts and carries the confidential scope.

It then exchanges that token again for its own: "the payments agent, acting for the user via
the concierge" (act nested). That is what the MCP gateway sees. The identity provider grants
at most what the user holds, so nothing in the chain can widen the user's consent.

It never sees a card number either. It passes an opaque vault reference and the server
de-tokenises internally, returning a masked receipt.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any, Awaitable, Callable, Dict, List

import uvicorn
from a2a.helpers import new_data_part, new_task_from_user_message, new_text_part
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes.agent_card_routes import create_agent_card_routes
from a2a.server.routes.fastapi_routes import add_a2a_routes_to_fastapi
from a2a.server.routes.jsonrpc_routes import create_jsonrpc_routes
from a2a.server.routes.rest_routes import create_rest_routes
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.types.a2a_pb2 import AgentCapabilities, AgentCard, AgentInterface, AgentSkill
from fastapi import FastAPI
from google.protobuf.json_format import MessageToDict

import agentid
import mcpgw
import tracing

log = logging.getLogger("payments")

AGENT_ID = os.getenv("AGENT_NAME", "demo2-payments-agent")
RUNTIME = os.getenv("AGENT_RUNTIME", "runtime-b")
PORT = int(os.getenv("AGENT_PORT", "8000"))
CONFIDENTIAL_TOOL = os.getenv("CONFIDENTIAL_TOOL", "charge_card")
CONFIDENTIAL_SCOPE = os.getenv("CONFIDENTIAL_SCOPE", "")
# Who may delegate to this agent: the concierge's client id and its identity (the act.sub of a
# token it exchanged). Written by the demo setup once the concierge's identity exists.
TRUSTED_CLIENTS = [s for s in os.getenv("TRUSTED_DELEGATOR_CLIENT_IDS", "").split(",") if s.strip()]
TRUSTED_ACTORS = [s for s in os.getenv("TRUSTED_DELEGATOR_SUBS", "").split(",") if s.strip()]
SKILL = "settle-payment"
RPC_PATH, REST_PATH = "/rpc", "/rest"


def hop(steps: List[Dict[str, Any]], name: str, credential: str,
        decision: str, detail: str, **extra: Any) -> Dict[str, Any]:
    row = {"hop": name, "credential": credential, "decision": decision,
           "detail": detail, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    row.update(extra)
    steps.append(row)
    return row


def token_view(tok: str) -> Dict[str, Any]:
    c = agentid.claims(tok)
    return {k: c.get(k) for k in ("iss", "sub", "act", "client_id", "aud", "scope", "exp")
            if c.get(k) is not None}


def bearer(headers: Dict[str, str]) -> str:
    """The caller's token. Agent Manager's gateway validates it and, with "forward token" on,
    sends it on as x-forwarded-authorization with the original Authorization header removed;
    a direct call (a local run) still carries Authorization."""
    h = {k.lower(): v for k, v in headers.items()}
    for name in ("x-forwarded-authorization", "authorization"):
        v = (h.get(name) or "").strip()
        if v.lower().startswith("bearer "):
            return v[7:].strip()
        if v and name == "x-forwarded-authorization" and v.count(".") == 2:   # forwarded without the prefix
            return v
    return ""


def check_delegation(tok: str) -> str:
    """Why this token is not an acceptable delegation, or "" if it is."""
    c = agentid.claims(tok)
    act = c.get("act") or {}
    if not tok:
        return "no token presented"
    if not act:
        return "not a delegation: the token has no actor (act), so nobody is acting for a user"
    if TRUSTED_CLIENTS and c.get("client_id") not in TRUSTED_CLIENTS:
        return f"issued to client {c.get('client_id')}, not to a trusted delegator"
    if TRUSTED_ACTORS and act.get("sub") not in TRUSTED_ACTORS:
        return f"the actor {act.get('sub')} is not a trusted delegator"
    if CONFIDENTIAL_SCOPE and CONFIDENTIAL_SCOPE not in (c.get("scope") or "").split():
        return f"the delegation does not carry {CONFIDENTIAL_SCOPE} (the user did not, or could not, grant it)"
    return ""


async def settle(tok: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """The work: verify the delegation, exchange it for this agent's own, charge through the gateway."""
    trace_id = args.get("trace_id") or ("txn-" + uuid.uuid4().hex[:16])
    steps: List[Dict[str, Any]] = []
    tracing.set_attributes(trace_id=trace_id, agent=AGENT_ID, runtime=RUNTIME)
    c = agentid.claims(tok)

    async with tracing.hop("verify_delegation", trace_id=trace_id, audience=AGENT_ID):
        why = check_delegation(tok)
        if why:
            hop(steps, "agent -> verify delegation", "AMP", "DENY", why, actor=AGENT_ID, token=token_view(tok))
            tracing.record_decision("DENY", "agent", why)
            return {"status": "denied", "at": "delegation", "trace_id": trace_id, "reason": why, "steps": steps}
        hop(steps, "agent -> verify delegation", "AMP", "ALLOW",
            f"delegated by {c['act'].get('sub')} (client {c.get('client_id')}) for user {c.get('sub')}",
            actor=AGENT_ID, token=token_view(tok))
        tracing.record_decision("ALLOW", "agent", "delegation from a trusted delegator",
                                delegator=c["act"].get("sub"), acting_for=c.get("sub"), credential_kind="AMP")

    gw = mcpgw.gateway_url()
    async with tracing.hop("token_exchange", trace_id=trace_id):
        try:
            mine = agentid.exchange(tok, scope=CONFIDENTIAL_SCOPE, resource=mcpgw.gateway_resource())
        except agentid.AgentIDError as exc:
            hop(steps, "agent -> IdP token exchange", "AMP", "DENY", str(exc))
            tracing.record_decision("DENY", "amp-idp", str(exc))
            return {"status": "failed", "at": "exchange", "trace_id": trace_id, "reason": str(exc), "steps": steps}
        hop(steps, "agent -> IdP token exchange", "AMP", "ALLOW",
            "this agent acting for the user, via the concierge (act nested); scope capped at the user's grant",
            actor=AGENT_ID, token=token_view(mine))
        tracing.record_decision("ALLOW", "amp-idp", "token exchange",
                                granted_scopes=(agentid.claims(mine).get("scope") or "").split())

    ctx = {"trace_id": trace_id, "actor": AGENT_ID, "runtime": RUNTIME, "user": c.get("sub"),
           "chain": [c.get("sub"), (c.get("act") or {}).get("sub"), AGENT_ID]}
    payment_ref = args.get("payment_ref", "tok_card_9931")
    amount = float(args.get("amount", 249.0))
    async with tracing.tool_call(CONFIDENTIAL_TOOL, trace_id=trace_id, tool=CONFIDENTIAL_TOOL, endpoint=gw,
                                 actor=AGENT_ID, payment_ref=payment_ref):
        out = mcpgw.call_tool(mine, CONFIDENTIAL_TOOL, {"payment_ref": payment_ref, "amount": amount},
                              trace_id=trace_id, context=ctx, url=gw)
        d = mcpgw.decision(out)
        hop(steps, "agent -> gateway -> mcp", "AMP", "ALLOW" if d["allowed"] else "DENY",
            f"{CONFIDENTIAL_TOOL}: {d['reason']}", actor=AGENT_ID, decided_by=d["by"],
            http_status=d["status"], endpoint=gw, result=d.get("result"))
        tracing.record_decision("ALLOW" if d["allowed"] else "DENY", d["by"], d["reason"], http_status=d["status"])

    return {"status": "ok" if d["allowed"] else "denied", "agent": AGENT_ID, "trace_id": trace_id,
            "acting_for": c.get("sub"), "delegated_by": (c.get("act") or {}).get("sub"),
            "payment_ref_used": payment_ref, "card_number_seen_by_agent": None,
            "receipt": d.get("result") if d["allowed"] else None, "steps": steps}


class PaymentsExecutor(AgentExecutor):
    """One skill, settle-payment. Its arguments come in the message metadata; its result is a
    JSON artifact, which is the audit record of this agent's part of the chain."""

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        await event_queue.enqueue_event(new_task_from_user_message(context.message))
        updater = TaskUpdater(event_queue, context.task_id, context.context_id)
        md = {**(context.metadata or {}),
              **(MessageToDict(context.message.metadata) if context.message is not None
                 and context.message.HasField("metadata") else {})}
        if md.get("skill", SKILL) != SKILL:
            await updater.reject(updater.new_agent_message([new_text_part(
                f"unknown skill {md.get('skill')!r}: this agent offers {SKILL}")]))
            return
        tok = bearer((context.call_context.state or {}).get("headers") or {})
        await updater.start_work()
        try:
            result = await settle(tok, md)
        except Exception as exc:                       # the task fails, the server stays up
            log.exception("settle failed")
            await updater.failed(updater.new_agent_message([new_text_part(f"failed: {exc}")]))
            return
        await updater.add_artifact([new_data_part(result)], name="settlement.json")
        msg = updater.new_agent_message([new_text_part(f"settlement {result['status']}")])
        if result["status"] == "ok":
            await updater.complete(msg)
        else:
            await updater.reject(msg)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        await TaskUpdater(event_queue, context.task_id, context.context_id).cancel()


def build_card() -> AgentCard:
    """The card the gateway serves (it rewrites the URLs to its own)."""
    base = (os.getenv("AGENT_PUBLIC_BASE_URL") or f"http://localhost:{PORT}").rstrip("/")
    return AgentCard(
        name=AGENT_ID, version="3.0.0",
        description="Settles payments on a stored instrument, acting for a user under a delegation "
                    "from a trusted agent. Never handles card numbers.",
        capabilities=AgentCapabilities(streaming=False, push_notifications=False),
        default_input_modes=["text/plain"], default_output_modes=["application/json"],
        supported_interfaces=[
            AgentInterface(url=f"{base}{RPC_PATH}", protocol_binding="JSONRPC", protocol_version="1.0"),
            AgentInterface(url=f"{base}{REST_PATH}", protocol_binding="HTTP+JSON", protocol_version="1.0")],
        skills=[AgentSkill(
            id=SKILL, name="Settle a payment",
            description='Charge a stored instrument by its vault reference. Metadata: '
                        '{"skill": "settle-payment", "amount": 249.0, "payment_ref": "tok_card_9931"}. '
                        "Requires a delegated token (token exchange) from a trusted delegator.",
            tags=["payments", "confidential"])],
    )


class DefaultProtocolVersion:
    """Stamp A2A-Version: 1.0 on direct calls that omit it (the gateway requires it anyway)."""

    def __init__(self, app: Callable) -> None:
        self.app = app

    async def __call__(self, scope: Dict[str, Any], receive: Callable[[], Awaitable[Dict[str, Any]]],
                       send: Callable[[Dict[str, Any]], Awaitable[None]]) -> None:
        if scope["type"] == "http" and not any(k.lower() == b"a2a-version" and v for k, v in scope["headers"]):
            scope = {**scope, "headers": [*scope["headers"], (b"a2a-version", b"1.0")]}
        await self.app(scope, receive, send)


card = build_card()
handler = DefaultRequestHandler(agent_executor=PaymentsExecutor(), task_store=InMemoryTaskStore(), agent_card=card)
app = FastAPI(title="Payments Agent (A2A)", version="3.0.0")
app.add_middleware(DefaultProtocolVersion)
add_a2a_routes_to_fastapi(
    app,
    agent_card_routes=create_agent_card_routes(card),
    jsonrpc_routes=create_jsonrpc_routes(handler, rpc_url=RPC_PATH),
    rest_routes=create_rest_routes(handler, path_prefix=REST_PATH),
)


@app.get("/whoami")
async def whoami():
    return {"agent": AGENT_ID, "runtime": RUNTIME, "protocol": "A2A 1.0", "skills": [SKILL],
            "agentid_configured": agentid.configured(), "mcp_gateway": mcpgw.endpoints(),
            "trusted_delegator_clients": TRUSTED_CLIENTS, "trusted_delegator_subs": TRUSTED_ACTORS,
            "confidential_scope": CONFIDENTIAL_SCOPE, "tracing": tracing.status()}


@app.get("/health")
async def health():
    return {"status": "ok", "service": AGENT_ID}


if __name__ == "__main__":
    # AMP's inputInterface declares port 8000 and its readiness probe is a TCP
    # check on it. The Google buildpack sets PORT=8080 in the image, so binding
    # $PORT would fail the probe. Bind 8000.
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
