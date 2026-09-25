"""
Spans for the hops this demo is actually about.

WHY THIS FILE EXISTS
--------------------
Agent Manager injects automatic instrumentation into every platform-hosted
agent: an init container installs Traceloop/OpenLLMetry, a sitecustomize hook
initialises it, and AMP_OTEL_ENDPOINT points at the gateway's /otel route. It
works -- a LangGraph agent in this same environment produces a full trace
without writing a line of telemetry code.

It produces nothing for these agents, though, and that is not a bug. Traceloop
instruments LLM SDKs, vector stores and agent frameworks, plus `requests` and
`urllib3`. These agents serve with FastAPI, call out with httpx, and never talk
to a model, so there is nothing for it to hook. Verified in the cluster: the
gateway had never received a single OTLP export from them.

Rewriting them as LangGraph graphs would make the auto-instrumentation notice
them, but it would add an LLM stack to agents whose entire job is minting
tokens and calling a gateway -- and the spans would still not carry the things
worth seeing here: which component refused a call, which scope was missing, and
the delegation chain. So the hops are instrumented explicitly instead, using
the SDK that is already present.

WHAT IT PRODUCES
----------------
    @agent_entry("settle_payment")      one root span per request, classified
                                        the same way AMP classifies a LangGraph
                                        agent
    async with hop("gateway -> mcp"):   one child span per hop

Each span carries amp.* attributes -- the transaction id, the acting agent, the
delegation chain, the decision and who made it -- and a refusal sets the span
status to ERROR, so denials show up in the trace rather than being invisible.

Nothing here is required for the agent to run. If the SDK is absent (running
the agent locally, say) every decorator and context manager degrades to a
no-op and the agent behaves identically.
"""

from __future__ import annotations

import contextvars
import functools
import os
import sys
from contextlib import asynccontextmanager, contextmanager
from typing import Any, Dict, Iterator, List, Optional

# The injected SDK is not on the default path; the sitecustomize hook that
# initialises it puts it here.
_SDK_PATH = os.getenv("AMP_OTEL_SDK_PATH", "/otel-tracing-sdk")
if os.path.isdir(_SDK_PATH) and _SDK_PATH not in sys.path:
    sys.path.append(_SDK_PATH)

TRACING = False
_tracer = None
_workflow_var: contextvars.ContextVar = contextvars.ContextVar(
    "amp_demo2_workflow", default="")

# Traceloop classifies a span with these two attributes. Setting them directly
# means one context manager covers every hop, instead of needing a decorator
# per function, and it keeps the spans in the same taxonomy the Console uses
# for automatically instrumented agents.
# Verified against the SDK in the runtime image:
#   TraceloopSpanKindValues = workflow | task | agent | tool | unknown
SPAN_KIND_ATTR = "traceloop.span.kind"
ENTITY_NAME_ATTR = "traceloop.entity.name"
WORKFLOW_NAME_ATTR = "traceloop.workflow.name"
VALID_KINDS = {"workflow", "task", "agent", "tool", "unknown"}

# Set once per request by agent_entry so every child span in the same trace
# carries the same workflow name and the Console groups them together.


try:  # pragma: no cover - depends on the runtime image
    from opentelemetry import trace as _trace
    from opentelemetry.trace import SpanKind, Status, StatusCode

    _tracer = _trace.get_tracer("wso2.amp.demo2")
    TRACING = True
except Exception:  # noqa: BLE001
    _trace = None  # type: ignore[assignment]
    SpanKind = Status = StatusCode = None  # type: ignore[assignment]


def _flatten(prefix: str, value: Any) -> Dict[str, Any]:
    """OTel attributes must be scalars or homogeneous sequences of scalars."""
    if value is None:
        return {}
    if isinstance(value, (str, bool, int, float)):
        return {prefix: value}
    if isinstance(value, (list, tuple)):
        return {prefix: [str(v) for v in value]}
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for k, v in value.items():
            out.update(_flatten(f"{prefix}.{k}", v))
        return out
    return {prefix: str(value)}


def attributes(**kw: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in kw.items():
        out.update(_flatten("amp." + k, v))
    return out


def set_attributes(**kw: Any) -> None:
    """Add amp.* attributes to whatever span is current."""
    if not TRACING:
        return
    span = _trace.get_current_span()
    if span is None:
        return
    for k, v in attributes(**kw).items():
        try:
            span.set_attribute(k, v)
        except Exception:  # noqa: BLE001
            pass


def record_decision(decision: str, decided_by: str = "", reason: str = "",
                    **extra: Any) -> None:
    """Record an authorization outcome on the current span.

    A refusal sets the span status to ERROR. That is the point: without it a
    denied call looks identical to an allowed one in the trace, and denials are
    most of what this demo is demonstrating.
    """
    if not TRACING:
        return
    set_attributes(decision=decision, decided_by=decided_by, reason=reason,
                   **extra)
    span = _trace.get_current_span()
    if span is None:
        return
    try:
        if decision in ("DENY", "BLOCK", "REVOKE", "RESTRICT"):
            span.set_status(Status(StatusCode.ERROR, f"{decision}: {reason}"[:200]))
        elif decision == "HITL":
            span.set_status(Status(StatusCode.OK, "held for human approval"))
        else:
            span.set_status(Status(StatusCode.OK))
    except Exception:  # noqa: BLE001
        pass


@contextmanager
def _span(name: str, kind: str, attrs: Dict[str, Any]) -> Iterator[Any]:
    if not TRACING:
        yield None
        return
    with _tracer.start_as_current_span(name, kind=SpanKind.INTERNAL) as span:
        try:
            span.set_attribute(SPAN_KIND_ATTR,
                               kind if kind in VALID_KINDS else "unknown")
            span.set_attribute(ENTITY_NAME_ATTR, name)
            wf = _workflow_var.get()
            if wf:
                span.set_attribute(WORKFLOW_NAME_ATTR, wf)
            for k, v in attrs.items():
                span.set_attribute(k, v)
        except Exception:  # noqa: BLE001
            pass
        try:
            yield span
        except Exception as exc:  # noqa: BLE001
            try:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR, str(exc)[:200]))
            except Exception:  # noqa: BLE001
                pass
            raise


@asynccontextmanager
async def hop(name: str, kind: str = "task", **kw: Any):
    """One span for one hop of the chain."""
    with _span(name, kind, attributes(**kw)) as span:
        yield span


@asynccontextmanager
async def tool_call(name: str, **kw: Any):
    """A tool invoked through the gateway. Classified as a tool span."""
    with _span(name, "tool", attributes(**kw)) as span:
        yield span


def agent_entry(name: str, **static: Any):
    """Decorate an agent's request handler as the root span of a trace.

    Classified as an agent span, which is how the Console labels an
    automatically instrumented agent, so these traces sit alongside those
    rather than looking like something else.
    """
    def decorate(fn):
        if not TRACING:
            return fn

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any):
            _workflow_var.set(name)
            with _span(name, "agent", attributes(**static)) as span:
                result = await fn(*args, **kwargs)
                try:
                    if isinstance(result, dict):
                        set_attributes(
                            trace_id=result.get("trace_id"),
                            status=result.get("status"),
                            delegation_chain=result.get("delegation_chain"))
                        if result.get("status") in ("denied", "failed"):
                            span.set_status(Status(
                                StatusCode.ERROR,
                                f"{result.get('status')} at {result.get('at', '?')}"))
                except Exception:  # noqa: BLE001
                    pass
                return result
        return wrapper
    return decorate


def status() -> Dict[str, Any]:
    """What /whoami reports about telemetry."""
    return {
        "enabled": TRACING,
        "sdk_path_present": os.path.isdir(_SDK_PATH),
        "otel_endpoint": os.getenv("AMP_OTEL_ENDPOINT", "") or None,
        "note": ("spans are emitted explicitly; the injected auto-instrumentation "
                 "only covers LLM frameworks, which these agents do not use"),
    }
