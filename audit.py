"""
The per-hop record: who acted, with which token content, and what was decided.

ThunderID does not nest `act` when a delegated token is exchanged again, so the
final token names only the last agent. The chain is therefore recorded here,
hop by hop, with each hop's token content, and sent to the control service
under the transaction id so the portal can show the whole path.

Each row also carries the id of the Agent Manager trace it was recorded in (the
auto-instrumentation's current OpenTelemetry span), so the portal can open the
platform's own trace for any hop of a transaction.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict, List, Optional

import httpx

from identity import UA

CONTROL_URL = os.getenv("CONTROL_SERVICE_URL", "").rstrip("/")


def trace_id() -> str:
    """The current Agent Manager (OpenTelemetry) trace id, or "" outside a traced run."""
    try:
        from opentelemetry import trace
        ctx = trace.get_current_span().get_span_context()
        return format(ctx.trace_id, "032x") if ctx.is_valid else ""
    except Exception:                       # no SDK in this runtime: nothing to link
        return ""

AGENT = os.getenv("AGENT_NAME", "agent")


class Trail:
    """Hops for one request. Returned to the caller and posted to the control service."""

    def __init__(self, txn: str):
        self.txn = txn
        self.hops: List[Dict[str, Any]] = []
        self.trace_ids: List[str] = []

    def hop(self, step: str, decision: str, detail: str, decided_by: str = "", token: Optional[Dict[str, Any]] = None,
            **extra: Any) -> Dict[str, Any]:
        row = {"txn": self.txn, "at": time.strftime("%H:%M:%S", time.gmtime()), "agent": AGENT, "step": step,
               "decision": decision, "decided_by": decided_by, "detail": detail}
        tid = trace_id()
        if tid:
            row["trace_id"] = tid
            if tid not in self.trace_ids:
                self.trace_ids.append(tid)
        if token:
            row["token"] = token
        row.update({k: v for k, v in extra.items() if v is not None})
        self.hops.append(row)
        _send([row])
        return row


def _send(rows: List[Dict[str, Any]]) -> None:
    if not CONTROL_URL:
        return

    def go() -> None:
        try:
            httpx.post(f"{CONTROL_URL}/audit", json={"rows": rows}, timeout=5, headers={"User-Agent": UA})
        except httpx.HTTPError:
            pass

    threading.Thread(target=go, daemon=True).start()
