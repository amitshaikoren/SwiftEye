"""
Per-artifact dissector registry for the forensic workspace (Velociraptor).

Mirrors the EID dissector pattern: each artifact dissector lives in its own
module and registers via @register_artifact_dissector("<Artifact.Name>").
dispatch_artifact() routes rows from one artifact file through its dissector.

To add a dissector:
  1. Create dissect_<shortname>.py with a fn decorated
     @register_artifact_dissector("Windows.System.SomeName").
  2. Import it at the bottom of this module so the decorator fires at startup.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from workspaces.forensic.parser.event import Event

logger = logging.getLogger("swifteye.forensic.artifact_dissectors")

# Row-level dissector: (row_dict, context_dict) -> Optional[Event]
DissectorFn = Callable[[Dict[str, Any], Dict[str, Any]], Optional[Event]]

ARTIFACT_DISSECTORS: Dict[str, DissectorFn] = {}


def register_artifact_dissector(artifact_name: str):
    """Decorator — registers a per-artifact row dissector."""
    def wrap(fn: DissectorFn) -> DissectorFn:
        ARTIFACT_DISSECTORS[artifact_name] = fn
        logger.debug("Registered artifact dissector: %s", artifact_name)
        return fn
    return wrap


def dispatch_artifact(
    artifact_name: str,
    rows: List[Dict[str, Any]],
    context: Optional[Dict[str, Any]] = None,
) -> List[Event]:
    """Route all rows from one artifact through its dissector.

    Unknown artifact names return an empty list — silent skip, same pattern
    as unknown EIDs in the EID dispatcher.
    """
    fn = ARTIFACT_DISSECTORS.get(artifact_name)
    if fn is None:
        return []
    ctx = context or {}
    events: List[Event] = []
    for row in rows:
        try:
            evt = fn(row, ctx)
            if evt is not None:
                events.append(evt)
        except Exception as exc:
            logger.warning("Artifact dissector error (%s): %s", artifact_name, exc)
    return events


# ── Auto-import dissectors so decorators fire ────────────────────────────────
from . import dissect_pslist   # noqa: E402, F401
from . import dissect_netstat  # noqa: E402, F401
