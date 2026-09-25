"""
The user end of the chain.

The first hop in the flow is a human, not an agent, so the demo needs a real
user token. It uses the one the operator already obtained from the Console's
authorization_code login and put in setup/.env -- the same token that drives
the Agent Manager API. It is a genuine OIDC token: RS256, issued by the
platform identity provider, carrying the user's subject, username and email.

Nothing here trusts it on sight. `verify` checks the signature against the
issuer's key set, plus the issuer and the expiry -- which is exactly what the
concierge agent does when the token arrives on an inbound request. That is the
point of the hop: the agent establishes WHO asked before it does anything on
their behalf.

The key set comes from one of two places. Run from the operator's machine, it
is fetched from the issuer's JWKS endpoint. Run inside an agent, it comes from
USER_JWKS_JSON, which the demo setup fetches once and pins into the agent's
configuration -- the issuer is a *.localhost name that does not resolve inside
the cluster, and an agent that cannot reach the key set would have to either
skip verification or refuse every request. Pinning keeps it cryptographic.

No password is ever handled here. Obtaining the token is the operator's own
browser login; this module only reads and verifies the result.
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.request
from typing import Any, Dict, Optional

PLATFORM_IDP = os.getenv("AMP_PLATFORM_IDP", "http://thunder.amp.localhost:8080")


class UserAuthError(RuntimeError):
    pass


def claims(token: str) -> Dict[str, Any]:
    """Unverified claims, for display."""
    try:
        p = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return {}


def header(token: str) -> Dict[str, Any]:
    try:
        p = token.split(".")[0]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return {}


def identity(token: str) -> Dict[str, Any]:
    """Who the token says the user is."""
    c = claims(token)
    return {"sub": c.get("sub", ""),
            "username": c.get("username") or c.get("email") or c.get("sub", ""),
            "email": c.get("email", ""),
            "groups": c.get("groups", []),
            "issuer": c.get("iss", ""),
            "expires_in": max(0, int(c.get("exp", 0) - time.time()))}


def _signing_key(token: str, iss: str) -> Any:
    """The key that signed this token: from the pinned key set, or the issuer."""
    import jwt
    kid = header(token).get("kid")
    pinned = os.getenv("USER_JWKS_JSON", "").strip()
    if pinned:
        try:
            keys = json.loads(pinned).get("keys", [])
        except Exception as exc:
            raise UserAuthError(f"USER_JWKS_JSON is not a JWKS: {exc}") from exc
        for k in keys:
            if k.get("kid") == kid:
                return jwt.PyJWK(k).key
        raise UserAuthError(
            f"the pinned key set has no key {kid} "
            f"(it has {[k.get('kid') for k in keys]}) — the identity provider "
            f"has rotated since setup ran; re-run it")
    from jwt import PyJWKClient
    try:
        return PyJWKClient(f"{iss}/oauth2/jwks", cache_keys=True) \
            .get_signing_key_from_jwt(token).key
    except Exception as exc:
        raise UserAuthError(
            f"could not fetch the signing key {kid} from {iss}: {exc}") from exc


def verify(token: str, *, issuer: Optional[str] = None) -> Dict[str, Any]:
    """Verify the user token's signature, issuer and expiry.

    Raises UserAuthError with the reason, so an agent can answer 401 with
    something a human can act on.
    """
    try:
        import jwt
    except ImportError as exc:                       # pragma: no cover
        raise UserAuthError("PyJWT[crypto] is required to verify user tokens") from exc

    iss = issuer or claims(token).get("iss") or PLATFORM_IDP
    key = _signing_key(token, iss)

    try:
        return jwt.decode(token, key,
                          algorithms=["RS256", "ES256", "PS256"],
                          issuer=iss,
                          options={"verify_aud": False})
    except Exception as exc:
        raise UserAuthError(f"user token rejected: {exc}") from exc


def describe(token: str) -> Dict[str, Any]:
    """Verify and summarise, without raising -- for printing in a scenario."""
    out = {"identity": identity(token), "verified": False, "reason": ""}
    try:
        verify(token)
        out["verified"] = True
    except UserAuthError as exc:
        out["reason"] = str(exc)
    return out
