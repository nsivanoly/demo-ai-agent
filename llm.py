"""
The model, reached only through this agent's Agent Manager LLM proxy.

Binding an LLM provider to the agent (a model config) makes Agent Manager inject
<CONFIG>_URL and <CONFIG>_API_KEY. The provider carries the guardrails (a regex
guardrail against prompt injection, PII redaction for card and ID numbers), so
every call this agent makes passes through them. A blocked prompt comes back as
HTTP 422 GUARDRAIL_INTERVENED.
"""

from __future__ import annotations

import os
from typing import Optional, Tuple

from gateway import internal

MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")


def _injected() -> Tuple[str, str]:
    url = key = ""
    for k, v in os.environ.items():
        if k.endswith("_LLM_URL") and not url:
            url = v
        elif k.endswith("_LLM_API_KEY") and not key:
            key = v
    return internal(url), key


def chat_model(temperature: float = 0.0):
    """A LangChain chat model pointed at the agent's LLM proxy (OpenAI-compatible)."""
    from langchain_openai import ChatOpenAI
    url, key = _injected()
    if not url:
        raise RuntimeError("no LLM proxy injected: bind the LLM provider to this agent (model config)")
    return ChatOpenAI(model=MODEL, temperature=temperature, base_url=url.rstrip("/") + "/v1",
                      api_key="unused", default_headers={"api-key": key, "User-Agent": "Trusted-Agents-Demo/1.0"},
                      max_retries=1, timeout=60)


def guardrail_verdict(exc: Exception) -> Optional[str]:
    """If an LLM call was refused by an Agent Manager guardrail, say why."""
    text = str(exc)
    if "GUARDRAIL_INTERVENED" in text or " 422" in text or "422 " in text:
        return "blocked by the Agent Manager guardrail (prompt injection pattern)"
    return None


def configured() -> bool:
    return bool(_injected()[0])
