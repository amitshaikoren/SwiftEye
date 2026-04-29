"""
Per-EID dissector dispatch.

Mirrors `workspaces/network/parser/l5_dispatch.py` — reads the EID off a
RawRecord, looks up the matching dissector in `DISSECTORS`, and returns
the normalized `Event` (or None if no dissector is registered for that EID).

Unknown EIDs are not errors — Sysmon logs contain many events the forensic
workspace doesn't yet know about. Silent skip matches the network pattern
for unknown protocols.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from workspaces.forensic.parser.event import Event

from . import DISSECTORS

logger = logging.getLogger("swifteye.forensic.dispatch")


def dispatch(raw: Dict[str, Any]) -> Optional[Event]:
    """Route a RawRecord to its per-EID dissector. Returns None if unknown."""
    eid = raw.get("eid")
    if not isinstance(eid, int):
        return None
    fn = DISSECTORS.get(eid)
    if fn is None:
        return None
    try:
        return fn(raw)
    except Exception as exc:
        logger.warning(
            "Dissector error for EID %s (record_id=%s): %s",
            eid, raw.get("record_id"), exc,
        )
        return None
