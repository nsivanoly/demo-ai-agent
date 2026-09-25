"""
On-behalf-of credentials for the agent-to-agent hop.

WHY THIS IS NOT RFC 8693
------------------------
The environment identity provider advertises the token-exchange grant:

    grant_types_supported: [... "urn:ietf:params:oauth:grant-type:token-exchange" ...]

but the OAuth client Agent Manager provisions for an AgentID is not authorized
to use it -- the token endpoint answers

    {"error":"unauthorized_client",
     "error_description":"The client is not authorized to use this grant type"}

for every RFC 8693 request shape, and neither the agent API nor the
agent-identity API exposes a grant-type field to change that. Registering a
client that IS authorized means the IdP's DCR endpoint, which refuses without
administrative credentials. This demo stays on Agent Manager, so it does not
go there.

So the A -> B hop carries the assertion below: the claim shape RFC 8693 would
produce (subject, actor, audience, delegation chain, narrowed scope, short
lifetime), signed and verified, but minted by the delegating agent rather than
by the IdP. Every scenario labels it [DEMO] for that reason.

What is NOT demo scaffolding: the token agent B then presents to the Agent
Manager gateway is a real AgentID access token, and the gateway's authorization
decision on it is real.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional

SIGNING_KEY = os.getenv("OBO_SIGNING_KEY", "demo2-obo-development-key")
DEFAULT_TTL = int(os.getenv("OBO_TTL_SECONDS", "120"))


class OBOError(RuntimeError):
    """The assertion was missing, malformed, expired or not for this audience."""


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _sign(signing_input: bytes, key: str) -> str:
    return _b64(hmac.new(key.encode(), signing_input, hashlib.sha256).digest())


def issue(*, actor: str, subject: str, audience: str, scope: List[str],
          delegation_chain: List[str], trace_id: str,
          actor_scopes: Optional[List[str]] = None,
          ttl_seconds: int = DEFAULT_TTL, kind: str = "obo",
          key: str = "", **extra: Any) -> str:
    """Mint an on-behalf-of assertion.

    `scope` must be a subset of `actor_scopes` when those are given: an agent
    cannot delegate authority it does not hold. That check lives here rather
    than at the receiving end so escalation fails at issue time, which is where
    a real authorization server would fail it.
    """
    if actor_scopes is not None and not set(scope) <= set(actor_scopes):
        raise OBOError(
            f"escalation refused: {sorted(set(scope) - set(actor_scopes))} "
            f"exceeds the delegating agent's own grant")

    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload: Dict[str, Any] = {
        "iss": actor,                  # the agent minting the assertion
        "sub": subject,                # the user the work is done for
        "aud": audience,               # the agent allowed to present it
        "act": {"sub": actor},         # RFC 8693 actor claim
        "scope": " ".join(scope),
        "delegation_chain": delegation_chain,
        "trace_id": trace_id,
        "cred_kind": "DEMO",
        "token_kind": kind,
        "jti": uuid.uuid4().hex,
        "iat": now, "nbf": now, "exp": now + ttl_seconds,
    }
    payload.update(extra)
    k = key or SIGNING_KEY
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(payload).encode())}".encode()
    return signing_input.decode() + "." + _sign(signing_input, k)


def claims(assertion: str) -> Dict[str, Any]:
    """Read the claims WITHOUT verifying. For display only."""
    try:
        return json.loads(_unb64(assertion.split(".")[1]))
    except Exception:
        return {}


def verify(assertion: str, *, audience: str, key: str = "") -> Dict[str, Any]:
    """Verify signature, lifetime and audience. Returns the claims."""
    k = key or SIGNING_KEY
    try:
        h, p, sig = assertion.split(".")
    except ValueError as exc:
        raise OBOError("assertion is not a JWT") from exc

    if not hmac.compare_digest(_sign(f"{h}.{p}".encode(), k), sig):
        raise OBOError("signature does not verify")

    c = json.loads(_unb64(p))
    now = int(time.time())
    if now >= c.get("exp", 0):
        raise OBOError(f"assertion expired {now - c.get('exp', 0)}s ago")
    if now < c.get("nbf", 0):
        raise OBOError("assertion is not yet valid")
    if c.get("aud") != audience:
        raise OBOError(f"assertion is for '{c.get('aud')}', not '{audience}'")
    return c


def revoked_marker(jti: str) -> str:
    return f"obo:{jti}"
