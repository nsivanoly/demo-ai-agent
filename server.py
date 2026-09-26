"""
Services MCP Server — tools for the Trusted Agents demo (demo 3).

Platform entrypoint object: `mcp` (file: server.py). A managed MCP host runs this
module as a stdio process and bridges it to HTTP; `main()` keeps it alive.

Three facts about where this runs shape the whole file:

  * It sits BEHIND the Agent Manager gateway, which authorizes every tool call
    against the scopes in the caller's token. There is no authorization here;
    repeating it would give policy two places to drift.
  * The gateway strips the caller's token, and under stdio no HTTP headers
    reach this process anyway. So the server never knows who called. Each tool
    accepts an optional `ctx` argument the calling agent fills in (transaction
    id, acting agent, user, delegation chain). It is ASSERTED context, echoed
    back so it lands in the agent's audit record, and never used to decide
    anything.
  * The host starts a fresh process per request, so the server is stateless.
    Approvals travel as signed references (see policy.py); the audit record and
    risk state live in the demo's control service.

Environment:
    APPROVAL_SIGNING_KEY   key for signed refund approvals (set it on the host)
    HITL_THRESHOLD         refunds above this need supervisor approval (default 500)
"""

from __future__ import annotations

import json
import os
import time
import uuid

os.environ.setdefault("FASTMCP_STATELESS_HTTP", "true")
os.environ.setdefault("FASTMCP_JSON_RESPONSE", "true")
os.environ.setdefault("FASTMCP_SHOW_SERVER_BANNER", "false")

import fastmcp  # noqa: E402
from fastmcp import FastMCP  # noqa: E402
from fastmcp.exceptions import ToolError  # noqa: E402

fastmcp.settings.stateless_http = True
fastmcp.settings.json_response = True

from typing import Any, Dict  # noqa: E402

import policy  # noqa: E402

mcp = FastMCP("services-mcp")

PROFILES = {
    "alex": {"profile_id": "RES-1001", "name": "Alex Morgan", "type": "resident",
             "national_id_ref": "tok_nid_0721", "payment_ref": "tok_card_9931"},
    "blake": {"profile_id": "BUS-2001", "name": "Blake Rivera", "type": "business owner",
              "national_id_ref": "tok_nid_3350", "payment_ref": "tok_card_4417"},
}
APPLICATIONS = {
    "APP-5001": {"application_id": "APP-5001", "owner": "alex", "service": "Trade licence renewal",
                 "status": "awaiting payment", "fee_due": 350.00},
    "APP-5002": {"application_id": "APP-5002", "owner": "blake", "service": "Commercial permit",
                 "status": "approved", "fee_due": 0.00, "paid": 1200.00, "overpaid": 900.00},
    "APP-5003": {"application_id": "APP-5003", "owner": "blake", "service": "Signage permit",
                 "status": "paid", "fee_due": 0.00, "paid": 180.00, "overpaid": 80.00},
}


class Refused(ToolError):
    """A call refused by application policy. Returned to the caller as a tool
    error, without the traceback FastMCP logs for unexpected exceptions."""


def _ctx(ctx: str) -> Dict[str, Any]:
    try:
        c = json.loads(ctx) if ctx else {}
        return c if isinstance(c, dict) else {}
    except ValueError:
        return {}


def _envelope(tool: str, ctx: str, result: Dict[str, Any]) -> Dict[str, Any]:
    """Attach the asserted caller context so the agent's audit record can join it."""
    c = _ctx(ctx)
    result["_call"] = {"tool": tool, "txn": c.get("txn") or c.get("trace_id") or "",
                       "asserted_actor": c.get("actor", ""), "asserted_user": c.get("user", ""),
                       "context_is": "asserted by the caller, not verified here", "at": int(time.time())}
    return result


def _check(tool: str, args: Dict[str, Any]) -> None:
    g = policy.guard(tool, args)
    if g["decision"] == "block":
        raise Refused(json.dumps({"status": "BLOCKED", "by": "server policy", "findings": g["findings"]}))


@mcp.tool
def get_profile(username: str, ctx: str = "") -> Dict[str, Any]:
    """A citizen or business profile. Sensitive values come back as vault references only."""
    _check("get_profile", {"username": username})
    p = PROFILES.get(username.lower())
    if not p:
        return _envelope("get_profile", ctx, {"error": "no such profile"})
    out = dict(p)
    out["national_id"] = policy.describe(p["national_id_ref"])["display"]
    return _envelope("get_profile", ctx, out)


@mcp.tool
def get_application_status(application_id: str, ctx: str = "") -> Dict[str, Any]:
    """Status of a service application."""
    _check("get_application_status", {"application_id": application_id})
    a = APPLICATIONS.get(application_id.upper())
    return _envelope("get_application_status", ctx, dict(a) if a else {"error": "no such application"})


@mcp.tool
def submit_application(service: str, details: str, ctx: str = "") -> Dict[str, Any]:
    """Submit a new service application."""
    _check("submit_application", {"service": service, "details": details})
    return _envelope("submit_application", ctx, {"application_id": "APP-" + uuid.uuid4().hex[:4].upper(),
                                                 "service": service, "status": "submitted"})


@mcp.tool
def pay_fee(application_id: str, payment_ref: str, amount: float, ctx: str = "") -> Dict[str, Any]:
    """Pay an application fee from a stored instrument.

    Takes a vault reference, never a card number. The vault de-tokenises inside
    this server and returns a masked receipt, so neither the agent nor the model
    ever handles the plaintext.
    """
    _check("pay_fee", {"application_id": application_id, "payment_ref": payment_ref, "amount": amount})
    if not payment_ref.startswith("tok_"):
        raise Refused(json.dumps({"status": "BLOCKED", "by": "server policy",
                                  "findings": [{"type": "not_a_vault_reference"}]}))
    receipt = policy.charge(payment_ref, amount, "AED", f"fee for {application_id}")
    if not receipt:
        return _envelope("pay_fee", ctx, {"error": "unknown payment reference"})
    return _envelope("pay_fee", ctx, receipt)


@mcp.tool
def request_refund(application_id: str, amount: float, reason: str = "", approval_ref: str = "",
                   ctx: str = "") -> Dict[str, Any]:
    """Refund an overpayment. Above the approval threshold it needs a supervisor's signed approval."""
    _check("request_refund", {"application_id": application_id, "amount": amount, "reason": reason})
    app = APPLICATIONS.get(application_id.upper())
    if not app:
        return _envelope("request_refund", ctx, {"error": "no such application"})
    if amount > float(app.get("overpaid", 0)) + 0.005:
        raise Refused(json.dumps({"status": "BLOCKED", "by": "server policy", "findings": [
            {"type": "refund_exceeds_overpayment", "detail": f"{amount} > {app.get('overpaid', 0)}"}]}))
    if amount > policy.HITL_THRESHOLD:
        if not approval_ref:
            return _envelope("request_refund", ctx, {
                "status": "HITL_REQUIRED", "request_id": policy.request_id(application_id, amount),
                "threshold": policy.HITL_THRESHOLD,
                "next": "a supervisor must call approve_refund; retry with the approval_ref it returns"})
        v = policy.verify_approval(approval_ref, application_id.upper(), amount)
        if not v["valid"]:
            raise Refused(json.dumps({"status": "BLOCKED", "by": "server policy",
                                      "findings": [{"type": "invalid_approval", "detail": v["reason"]}]}))
        return _envelope("request_refund", ctx, {"refund_id": "rfnd_" + uuid.uuid4().hex[:10], "status": "refunded",
                                                 "amount": amount, "approved_by": v["approved_by"]})
    return _envelope("request_refund", ctx, {"refund_id": "rfnd_" + uuid.uuid4().hex[:10], "status": "refunded",
                                             "amount": amount, "approved_by": "auto (below threshold)"})


@mcp.tool
def approve_refund(application_id: str, amount: float, approver: str, ctx: str = "") -> Dict[str, Any]:
    """Supervisor approval for a refund above the threshold.

    The gateway only lets this through for a token carrying refund:approve, so
    reaching this code at all is the authorization. It returns a signed,
    short-lived approval reference for request_refund.
    """
    _check("approve_refund", {"application_id": application_id, "amount": amount, "approver": approver})
    return _envelope("approve_refund", ctx, {
        "approval_ref": policy.sign_approval(application_id.upper(), amount, approver),
        "request_id": policy.request_id(application_id.upper(), amount),
        "valid_for_seconds": policy.APPROVAL_TTL_SECONDS, "signing_key": policy.SIGNING_KEY_SOURCE})


@mcp.tool
def describe_payment_reference(payment_ref: str, ctx: str = "") -> Dict[str, Any]:
    """What a vault reference points to, masked. The plaintext is never returned."""
    return _envelope("describe_payment_reference", ctx,
                     policy.describe(payment_ref) or {"error": "unknown reference"})


@mcp.tool
def whoami(ctx: str = "") -> Dict[str, Any]:
    """What this server knows about the caller: only what the caller asserted."""
    return _envelope("whoami", ctx, {"verified_identity": None,
                                     "why": "the gateway strips the caller's token; identity is decided at the gateway"})


def main() -> None:
    """Run over stdio. A managed host launches this module and bridges it to HTTP."""
    mcp.run()


if __name__ == "__main__":
    main()
