"""
The user end of the chain.

The first hop in the flow is a human, not an agent, so the demo needs a real
user token. It uses the one the operator already obtained from the Console's
authorization_code login and put in setup/.env -- the same token that drives
the Agent Manager API. It is a genuine OIDC token: RS256, issued by the
platform identity provider, carrying the user's subject, username and email.

Nothing here trusts it on sight. `verify` fetches the issuer's JWKS and checks
the signature, the issuer and the expiry, which is exactly what the concierge
agent does when the token arrives on an inbound request. That is the point of
the hop: the agent establishes WHO asked before it does anything on their
behalf.

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


def verify(token: str, *, issuer: Optional[str] = None) -> Dict[str, Any]:
    """Verify the user token against its issuer's live JWKS.

    Raises UserAuthError with the reason, so an agent can answer 401 with
    something a human can act on.
    """
    try:
        import jwt
        from jwt import PyJWKClient
    except ImportError as exc:                       # pragma: no cover
        raise UserAuthError("PyJWT[crypto] is required to verify user tokens") from exc

    iss = issuer or claims(token).get("iss") or PLATFORM_IDP
    kid = header(token).get("kid")
    try:
        jwks = PyJWKClient(f"{iss}/oauth2/jwks", cache_keys=True)
        key = jwks.get_signing_key_from_jwt(token).key
    except Exception as exc:
        raise UserAuthError(f"could not fetch the signing key {kid} from {iss}: {exc}") from exc

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
