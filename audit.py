"""
The per-hop record: who acted, with which token content, and what was decided.

ThunderID does not nest `act` when a delegated token is exchanged again, so the
final token names only the last agent. The chain is therefore recorded here,
hop by hop, with each hop's token content, and sent to the control service
under the transaction id so the portal can show the whole path.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict, List, Optional

import httpx

from identity import UA

CONTROL_URL = os.getenv("CONTROL_SERVICE_URL", "").rstrip("/")
AGENT = os.getenv("AGENT_NAME", "agent")


class Trail:
    """Hops for one request. Returned to the caller and posted to the control service."""

    def __init__(self, txn: str):
        self.txn = txn
        self.hops: List[Dict[str, Any]] = []

    def hop(self, step: str, decision: str, detail: str, decided_by: str = "", token: Optional[Dict[str, Any]] = None,
            **extra: Any) -> Dict[str, Any]:
        row = {"txn": self.txn, "at": time.strftime("%H:%M:%S", time.gmtime()), "agent": AGENT, "step": step,
               "decision": decision, "decided_by": decided_by, "detail": detail}
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
