"""
Under the hood: every outbound HTTP call this agent makes while handling a request.

httpx is wrapped once, so the calls come from the real clients (token requests,
token exchanges, gateway tool calls, the LLM, the other agent) with no change to
the code that makes them. Each call is recorded against the request being
handled and returned with the response, for the portal to show.

Nothing secret leaves the agent: bearer tokens, API keys, client secrets, the
subject and actor tokens of an exchange, and any JWT inside a body are masked
before the record is kept.
"""

from __future__ import annotations

import contextvars
import json
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl

import httpx

_active: contextvars.ContextVar[Optional[List[Dict[str, Any]]]] = contextvars.ContextVar("http_trace", default=None)

SECRET_HEADERS = {"authorization", "x-forwarded-authorization", "api-key", "x-api-key", "cookie", "set-cookie"}
SECRET_FIELDS = {"client_secret", "subject_token", "actor_token", "access_token", "refresh_token", "id_token",
                 "password", "approval_ref", "code", "code_verifier"}
JWT = re.compile(r"eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}")
BODY_LIMIT = 3000
AGENT = ""


def start(agent: str) -> List[Dict[str, Any]]:
    """Begin recording for the request being handled; returns the list calls go into."""
    global AGENT
    AGENT = agent
    calls: List[Dict[str, Any]] = []
    _active.set(calls)
    return calls


def _mask_value(v: str) -> str:
    v = str(v)
    if v.lower().startswith("bearer "):
        return f"Bearer ‹masked, {len(v) - 7} chars›"
    return f"‹masked, {len(v)} chars›" if v else v


def _mask_text(text: str) -> str:
    return JWT.sub(lambda m: f"‹JWT masked, {len(m.group())} chars›", text)


def _body(raw: bytes, ctype: str) -> Any:
    if not raw:
        return None
    text = raw.decode("utf-8", "replace")
    try:
        if "application/x-www-form-urlencoded" in ctype:
            return {k: (_mask_value(v) if k in SECRET_FIELDS else v) for k, v in parse_qsl(text, keep_blank_values=True)}
        if "json" in ctype or text[:1] in "{[":
            data = json.loads(text)
            return json.loads(_mask_text(json.dumps(_mask_json(data))))
    except ValueError:
        pass
    text = _mask_text(text)
    return text[:BODY_LIMIT] + ("…" if len(text) > BODY_LIMIT else "")


def _mask_json(o: Any) -> Any:
    if isinstance(o, dict):
        return {k: (_mask_value(v) if k in SECRET_FIELDS and isinstance(v, str) else _mask_json(v)) for k, v in o.items()}
    if isinstance(o, list):
        return [_mask_json(x) for x in o]
    return o


def _clip(o: Any) -> Any:
    s = json.dumps(o, default=str)
    if len(s) <= BODY_LIMIT:
        return o
    return s[:BODY_LIMIT] + "…"


def _headers(h: Any) -> List[List[str]]:
    return [[k, _mask_value(v) if k.lower() in SECRET_HEADERS else v] for k, v in h.items()]


def _wrap(orig):
    """A send() that records the call, for any httpx-compatible client class."""
    def send(self, request, *a: Any, **k: Any):
        return _record(orig, self, request, *a, **k)
    return send


def _record(orig, self, request, *a: Any, **k: Any):
    calls = _active.get()
    if calls is None:
        return orig(self, request, *a, **k)
    t0 = time.time()
    try:
        response = orig(self, request, *a, **k)
    except Exception as e:
        calls.append({"agent": AGENT, "method": request.method, "url": str(request.url), "status": 0,
                      "reason": type(e).__name__, "duration_ms": int((time.time() - t0) * 1000), "ts": int(t0),
                      "request_headers": _headers(request.headers),
                      "request_body": _clip(_body(request.content, request.headers.get("content-type", ""))),
                      "response_headers": [], "response_body": str(e)[:300]})
        raise
    try:
        response.read()
        rbody = _clip(_body(response.content, response.headers.get("content-type", "")))
    except Exception:
        rbody = "‹streamed›"
    calls.append({"agent": AGENT, "method": request.method, "url": str(request.url), "status": response.status_code,
                  "reason": response.reason_phrase, "duration_ms": int((time.time() - t0) * 1000), "ts": int(t0),
                  "request_headers": _headers(request.headers),
                  "request_body": _clip(_body(request.content, request.headers.get("content-type", ""))),
                  "response_headers": _headers(response.headers), "response_body": rbody})
    return response


# Installed on import. The OpenAI SDK (used for the LLM) ships its own copy of httpx as
# "httpx2", so both are wrapped, or the model calls would be missing.
httpx.Client.send = _wrap(httpx.Client.send)
try:
    import httpx2
    httpx2.Client.send = _wrap(httpx2.Client.send)
except ImportError:
    pass
