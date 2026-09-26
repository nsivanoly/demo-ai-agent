"""
This agent's identity, and the delegation it acts under.

AgentID: Agent Manager injects the agent's OAuth client into the pod as
AMP_AGENTID_CLIENT_ID / _CLIENT_SECRET / _TOKEN_ENDPOINT / _SCOPES. Nothing here
is configured by hand.

Delegation (on behalf of a user) is a real RFC 8693 token exchange at the
environment ThunderID. Three rules, each from something observed on this
platform:

  * Always send actor_token. ThunderID adds the `act` claim (who is acting)
    only when the actor token is present.
  * Always send resource=<the MCP gateway>. Delegated scopes come from the
    subject token and are bound to one resource; without it a user's unrelated
    scopes can carry over.
  * Cap the requested scopes at THIS agent's own grant. ThunderID does not apply
    the agent's roles to a delegated token, so the agent applies them itself.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

UA = "Trusted-Agents-Demo/1.0"
CLIENT_ID = os.getenv("AMP_AGENTID_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("AMP_AGENTID_CLIENT_SECRET", "")
TOKEN_ENDPOINT = os.getenv("AMP_AGENTID_TOKEN_ENDPOINT", "")
# The agent's own grant: written by setup after roles are assigned, because
# AMP_AGENTID_SCOPES is computed at creation, before any role exists.
OWN_SCOPES = (os.getenv("AGENT_ROLE_SCOPES") or os.getenv("AMP_AGENTID_SCOPES", "")).split()
MCP_RESOURCE = os.getenv("MCP_RESOURCE", "")
# Verified subject (sub) -> citizen record, written by setup. A record is looked up by
# the token's subject, which the IdP always issues, never by the username claim alone:
# that is an optional attribute the user can decline on the consent screen.
SUBJECTS: Dict[str, str] = json.loads(os.getenv("SUBJECT_DIRECTORY", "{}") or "{}")

TX = "urn:ietf:params:oauth:grant-type:token-exchange"
AT = "urn:ietf:params:oauth:token-type:access_token"

_cache: Dict[Tuple[str, str], Tuple[str, float]] = {}
_lock = threading.Lock()


class IdentityError(Exception):
    pass


def configured() -> bool:
    return bool(CLIENT_ID and CLIENT_SECRET and TOKEN_ENDPOINT)


def claims(token: str) -> Dict[str, Any]:
    try:
        p = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return {}


def scopes_of(token: str) -> List[str]:
    return (claims(token).get("scope") or "").split()


def citizen(token: str) -> str:
    """The citizen record this token is for: by verified subject first, then the username claim."""
    c = claims(token)
    return SUBJECTS.get(c.get("sub", "")) or c.get("username") or ""


def view(token: str) -> Dict[str, Any]:
    """The token content shown in the audit record: claims only, never the token."""
    c = claims(token)
    out = {k: c.get(k) for k in ("sub", "client_id", "aud", "scope", "iss") if c.get(k) is not None}
    if c.get("act"):
        out["act"] = c["act"].get("sub")
    if c.get("username"):
        out["username"] = c["username"]
    if c.get("exp"):
        out["expires_in"] = int(c["exp"] - time.time())
    return out


def _post(form: Dict[str, str]) -> Dict[str, Any]:
    if not configured():
        raise IdentityError("AgentID is not provisioned for this environment yet (AMP_AGENTID_* not injected)")
    r = httpx.post(TOKEN_ENDPOINT, data=form, auth=(CLIENT_ID, CLIENT_SECRET),
                   headers={"User-Agent": UA}, timeout=15)
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"raw": r.text[:200]}
    if r.status_code != 200 or "access_token" not in body:
        raise IdentityError(f"token endpoint {r.status_code}: {body.get('error_description') or body.get('error') or body}")
    return body


def own_token(scope: Optional[List[str]] = None, resource: str = "") -> str:
    """This agent's own client_credentials token, cached per (resource, scope)."""
    resource = resource or MCP_RESOURCE
    want = " ".join(scope if scope is not None else OWN_SCOPES)
    key = (resource, want)
    with _lock:
        hit = _cache.get(key)
        if hit and hit[1] - time.time() > 30:
            return hit[0]
    form = {"grant_type": "client_credentials", "resource": resource}
    if want:
        form["scope"] = want
    body = _post(form)
    tok = body["access_token"]
    with _lock:
        _cache[key] = (tok, time.time() + int(body.get("expires_in", 300)) * 0.75)
    return tok


def live_grant() -> List[str]:
    """This agent's grant as the IdP sees it RIGHT NOW: a fresh client_credentials
    token asking for everything the agent was set up with, which ThunderID filters
    to the agent's current AMP roles. Not cached, so removing a role restricts the
    agent on its very next delegation."""
    form = {"grant_type": "client_credentials", "resource": MCP_RESOURCE, "scope": " ".join(OWN_SCOPES)}
    return scopes_of(_post(form)["access_token"])


def cap(requested: List[str]) -> Tuple[List[str], List[str]]:
    """Split requested scopes into (within this agent's live grant, beyond it)."""
    own = set(live_grant())
    return [s for s in requested if s in own], [s for s in requested if s not in own]


def delegate(subject_token: str, scopes: List[str], resource: str = "", apply_cap: bool = True) -> Dict[str, Any]:
    """Exchange a user's (or a delegating agent's) token for one this agent can use.

    Returns {"token", "requested", "capped_out", "granted", "view"}.
    """
    resource = resource or MCP_RESOURCE
    within, beyond = cap(scopes) if apply_cap else (scopes, [])
    if not within:
        raise IdentityError(f"nothing to request: {beyond} are outside this agent's own grant {OWN_SCOPES}")
    actor = own_token()
    body = _post({"grant_type": TX, "subject_token": subject_token, "subject_token_type": AT,
                  "actor_token": actor, "actor_token_type": AT,
                  "resource": resource, "scope": " ".join(within)})
    tok = body["access_token"]
    return {"token": tok, "requested": scopes, "capped_out": beyond, "granted": scopes_of(tok), "view": view(tok),
            "actor_view": view(actor), "subject_view": view(subject_token)}
