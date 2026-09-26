"""
Per-call policy, the vault, and signed approvals.

Everything here is stateless on purpose. The managed host starts a fresh
process for each request, so nothing can be remembered between calls: no audit
log, no counters, no pending approvals. Each call is judged on its own inputs,
and anything that needs memory lives in the demo's control service instead.

Authorization is NOT here. The Agent Manager gateway in front of this server
checks every tool call against the scopes in the caller's token before the call
arrives. What remains is application policy: input guardrails, value limits,
and the vault.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional

HITL_THRESHOLD = float(os.getenv("HITL_THRESHOLD", "500"))
APPROVAL_TTL_SECONDS = int(os.getenv("APPROVAL_TTL_SECONDS", "600"))

# The approval signing key comes from the host's environment. Without one the
# server still works, but says so in every approval it issues, because a key
# baked into public source code proves nothing.
_ENV_KEY = os.getenv("APPROVAL_SIGNING_KEY", "")
SIGNING_KEY = (_ENV_KEY or "demo-only-insecure-default-key").encode()
SIGNING_KEY_SOURCE = "environment" if _ENV_KEY else "built-in default (insecure)"


# ---------------------------------------------------------------------------
# Guardrails
# ---------------------------------------------------------------------------

INJECTION = [
    r"ignore (all )?(previous|prior) instructions",
    r"disregard (your|the) (rules|policy|guardrails)",
    r"reveal (your )?(system prompt|instructions)",
    r"you are now (in )?(developer|god|admin) mode",
]
RAW_CARD = r"\b(?:\d[ -]?){13,19}\b"
RAW_NATIONAL_ID = r"\b\d{3}-?\d{4}-?\d{7}-?\d\b|\b\d{12}\b"


def guard(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Inspect a call's inputs. Returns {"decision": allow|block, "findings": [...]}."""
    text = " ".join(str(v) for k, v in args.items() if k != "ctx")
    findings: List[Dict[str, str]] = []
    for pat in INJECTION:
        if re.search(pat, text, re.I):
            findings.append({"type": "prompt_injection", "severity": "high",
                             "detail": f"input matches /{pat}/"})
            break
    if re.search(RAW_CARD, text):
        findings.append({"type": "raw_card_number", "severity": "critical",
                         "detail": "a raw card number was supplied; only vault references are accepted"})
    if re.search(RAW_NATIONAL_ID, text):
        findings.append({"type": "raw_national_id", "severity": "critical",
                         "detail": "a raw national ID was supplied; only vault references are accepted"})
    return {"decision": "block" if findings else "allow", "findings": findings, "tool": tool}


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------
# The only copy of the sensitive values. Agents and the model only ever hold the
# opaque reference; the plaintext is used inside this module and never returned.

_VAULT: Dict[str, Dict[str, str]] = {
    "tok_card_9931": {"type": "card", "pan": "4539871233449931", "holder": "Alex Morgan"},
    "tok_card_4417": {"type": "card", "pan": "5412753456784417", "holder": "Blake Rivera"},
    "tok_nid_0721": {"type": "national_id", "value": "784198712345672", "holder": "Alex Morgan"},
    "tok_nid_3350": {"type": "national_id", "value": "784199054321350", "holder": "Blake Rivera"},
}


def describe(ref: str) -> Optional[Dict[str, Any]]:
    rec = _VAULT.get(ref)
    if not rec:
        return None
    shown = (f"card ending {rec['pan'][-4:]}" if rec["type"] == "card"
             else f"national ID ending {rec['value'][-4:]}")
    return {"reference": ref, "type": rec["type"], "display": shown, "plaintext_returned": False}


def charge(ref: str, amount: float, currency: str, purpose: str) -> Optional[Dict[str, Any]]:
    """De-tokenise inside the vault, charge, and return only a masked receipt."""
    rec = _VAULT.get(ref)
    if not rec or rec["type"] != "card":
        return None
    pan = rec["pan"]
    network = "visa" if pan.startswith("4") else "mastercard"
    last4 = pan[-4:]
    del pan
    return {"receipt_id": "rcpt_" + uuid.uuid4().hex[:12], "status": "captured",
            "amount": round(amount, 2), "currency": currency, "purpose": purpose,
            "instrument": f"{network} ****{last4}", "plaintext_exposed": False}


# ---------------------------------------------------------------------------
# Signed approvals (stateless human-in-the-loop)
# ---------------------------------------------------------------------------
# A refund above the threshold cannot execute until a supervisor approves it.
# The server cannot remember a pending request, so the approval travels as a
# signed reference: approve_refund issues it, request_refund verifies it. The
# supervisor's authority is checked by the gateway (scope refund:approve) when
# approve_refund is called, so the signature only has to prove "this server
# issued this approval, for this refund, recently".

def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def request_id(application_id: str, amount: float) -> str:
    return "rfq_" + hashlib.sha256(f"{application_id}|{amount:.2f}".encode()).hexdigest()[:12]


def sign_approval(application_id: str, amount: float, approver: str) -> str:
    body = {"rid": request_id(application_id, amount), "app": application_id,
            "amt": round(amount, 2), "by": approver, "exp": int(time.time()) + APPROVAL_TTL_SECONDS}
    raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(SIGNING_KEY, raw, hashlib.sha256).digest()
    return f"apr.{_b64(raw)}.{_b64(sig)}"


def verify_approval(ref: str, application_id: str, amount: float) -> Dict[str, Any]:
    try:
        tag, raw_b64, sig_b64 = ref.split(".")
        raw = _unb64(raw_b64)
        if tag != "apr" or not hmac.compare_digest(hmac.new(SIGNING_KEY, raw, hashlib.sha256).digest(), _unb64(sig_b64)):
            return {"valid": False, "reason": "signature does not verify"}
        body = json.loads(raw)
    except Exception:
        return {"valid": False, "reason": "malformed approval reference"}
    if body.get("exp", 0) < time.time():
        return {"valid": False, "reason": "approval has expired"}
    if body.get("app") != application_id or abs(float(body.get("amt", -1)) - amount) > 0.005:
        return {"valid": False, "reason": "approval is for a different refund"}
    return {"valid": True, "approved_by": body.get("by"), "request_id": body.get("rid")}
