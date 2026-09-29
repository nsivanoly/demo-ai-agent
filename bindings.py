"""
What Agent Manager injects when an LLM provider and an MCP server are attached to the agent.

Attaching them (at create time, in the agent's modelConfig and mcpConfig) makes
Agent Manager inject each one's URL and API key as environment variables, under
the names given in the attachment. Setup names them the same in every agent:

    LLM_URL, LLM_API_KEY    the agent's LLM proxy (guardrailed provider)
    MCP_URL                 the MCP gateway proxy; also the audience tokens are issued for

Nothing here is hard-coded. If an agent was attached without explicit names,
Agent Manager's defaults (<AGENT>_LLM_URL, <AGENT>_MCP_CONFIG_URL, ...) are found
by suffix, and a URL that setup wrote directly (older deployments) is the last resort.
"""

from __future__ import annotations

import os

SUFFIXES = {
    "LLM_URL": ("_LLM_URL",),
    "LLM_API_KEY": ("_LLM_API_KEY",),
    "MCP_URL": ("_MCP_CONFIG_URL", "_MCP_URL"),
    "MCP_API_KEY": ("_MCP_CONFIG_API_KEY", "_MCP_API_KEY"),
}


def injected(name: str, fallback: str = "") -> str:
    """The value Agent Manager injected for `name` (see SUFFIXES), else os.environ[fallback]."""
    if os.getenv(name):
        return os.environ[name]
    for k in sorted(os.environ):
        if k.endswith(SUFFIXES.get(name, ())):
            return os.environ[k]
    return os.getenv(fallback, "") if fallback else ""


def source(name: str, fallback: str = "") -> str:
    """Which variable `injected(name)` read, for the agent's /health and the portal."""
    if os.getenv(name):
        return name
    for k in sorted(os.environ):
        if k.endswith(SUFFIXES.get(name, ())):
            return k
    return fallback if fallback and os.getenv(fallback) else ""


def report() -> dict:
    """Which variable each binding came from (names only, never values)."""
    return {"LLM_URL": source("LLM_URL"), "LLM_API_KEY": source("LLM_API_KEY"),
            "MCP_URL": source("MCP_URL", fallback="MCP_RESOURCE")}
