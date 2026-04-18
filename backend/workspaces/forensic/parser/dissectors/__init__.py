"""
Per-EID dissector registry for the forensic workspace.

Mirrors `workspaces/network/parser/protocols/` — each dissector lives in
its own `dissect_eid<N>.py` and decorates itself with `@register_dissector(N)`.
`dispatch.py` routes raw records through this registry.

To add a dissector:
  1. Create `dissect_eidN.py` with a function decorated `@register_dissector(N)`.
  2. Import it at the bottom of this module so the decorator fires at startup.
"""

from __future__ import annotations

from typing import Callable, Dict, Optional

from workspaces.forensic.parser.event import Event

# RawRecord → Event (or None if the dissector decides to drop it).
DissectorFn = Callable[[Dict], Optional[Event]]

# EID → dissector function. Populated by @register_dissector when each
# dissect_eid*.py module is imported below.
DISSECTORS: Dict[int, DissectorFn] = {}


def register_dissector(eid: int):
    """Decorator — registers a per-EID dissector function."""
    def wrap(fn: DissectorFn) -> DissectorFn:
        DISSECTORS[eid] = fn
        return fn
    return wrap


# ── Auto-import dissectors so decorators fire ────────────────────────────
from . import dissect_eid1  # noqa: E402, F401
