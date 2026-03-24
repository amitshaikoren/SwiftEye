"""
Auto-discovery registry for protocol field handlers.

Each module in this package defines three required functions and one optional:
    init()                              → dict of initial session fields for this protocol
    accumulate(s, ex, is_fwd, source_type) → mutate session dict from one packet's extra
    serialize(s)                        → convert working fields (sets, etc.) to JSON-safe output
    check_boundary(flow_state, ex)      → (optional) return True to split session on this packet

Modules are auto-discovered on import. Drop a new file here and it just works —
no changes to sessions.py needed.

Key variables used across protocol field modules:
    s           — the session dict being built (mutable, one per 5-tuple)
    ex          — pkt.extra dict from the current packet (read-only)
    is_fwd      — bool: True if this packet is from the session initiator
    source_type — str or None: which adapter produced this packet. Determines
                  how direction and field merging behave for multi-source data.
                  Set by each adapter in pkt.extra["source_type"].

                  Valid values:
                    None   — pcap/pcapng (raw packets, direction from TCP flags / first-packet)
                    "zeek" — Zeek log adapter (pre-aggregated, one record = both directions)

                  Planned:
                    "splunk" — Splunk CSV/JSON export
                    "sysmon" — Sysmon XML/JSON event logs
                    "netflow" — Netflow/IPFIX records

                  When adding a new adapter, add its source_type string here.

Lazy initialization:
    Protocol fields are NOT pre-loaded onto every session. Instead, each protocol's
    init() is called only when its accumulator first encounters relevant data.
    A session that never sees DNS traffic will have no dns_* fields — zero data noise.

    Mechanism: accumulate() calls run without init. If the accumulator accesses a field
    that doesn't exist (KeyError), we catch it, run init(), and retry. This works because
    accumulators always check ex.get() (no mutation) before accessing s[] (mutation),
    so the KeyError fires before any partial state changes.
"""

import importlib
import pkgutil
from typing import Callable, Dict, Any, List, Tuple

# ── Serialize-time cap ───────────────────────────────────────────────
# Generous safety valve applied only when sending data to the frontend.
# During accumulation, data grows unbounded. This prevents pathological
# sessions (e.g. web crawler with 10K URIs) from blowing up memory.
# When a field is capped, a companion _total key is added so the
# frontend can show "Showing X of Y".
SERIALIZE_CAP = 500


def cap_list(s: dict, key: str, limit: int = SERIALIZE_CAP):
    """Cap a list field in-place and add a _total count if truncated."""
    lst = s.get(key, [])
    if len(lst) > limit:
        s[f"{key}_total"] = len(lst)
        s[key] = lst[:limit]

# Each entry: (init_fn, accumulate_fn, serialize_fn)
_REGISTRY: List[Tuple[Callable, Callable, Callable]] = []

# Protocol-specific boundary checkers: [(check_boundary_fn, ...)]
# Called by sessions.py to detect application-layer session boundaries.
_BOUNDARY_CHECKERS: List[Callable] = []


def _discover():
    """Import all sibling modules and collect their init/accumulate/serialize."""
    for _importer, modname, _ispkg in pkgutil.iter_modules(__path__):
        mod = importlib.import_module(f".{modname}", __name__)
        init_fn = getattr(mod, "init", None)
        acc_fn = getattr(mod, "accumulate", None)
        ser_fn = getattr(mod, "serialize", None)
        if init_fn and acc_fn and ser_fn:
            _REGISTRY.append((init_fn, acc_fn, ser_fn))
        boundary_fn = getattr(mod, "check_boundary", None)
        if boundary_fn:
            _BOUNDARY_CHECKERS.append(boundary_fn)


def any_boundary(flow_state: dict, ex: dict) -> bool:
    """Run all protocol boundary checkers. Returns True if any says split."""
    for fn in _BOUNDARY_CHECKERS:
        if fn(flow_state, ex):
            return True
    return False


def all_accumulate(s: dict, ex: dict, is_fwd: bool, source_type: str = None):
    """Run all protocol accumulators on one packet with lazy init.

    Each protocol is initialized only when its accumulator first tries to access
    session fields (KeyError on uninitialized field → init → retry).
    Protocols that never see relevant data are never initialized.
    """
    active = s.get("_active_protocols")
    if active is None:
        active = set()
        s["_active_protocols"] = active

    for i, (init_fn, acc_fn, _) in enumerate(_REGISTRY):
        if i in active:
            acc_fn(s, ex, is_fwd, source_type)
        else:
            try:
                acc_fn(s, ex, is_fwd, source_type)
            except KeyError:
                # Accumulator tried to access its fields but they don't exist yet.
                # Init this protocol's fields and retry.
                s.update(init_fn())
                active.add(i)
                acc_fn(s, ex, is_fwd, source_type)


def all_serialize(s: dict):
    """Run only active protocol serializers on a completed session."""
    active = s.get("_active_protocols", set())
    for i, (_, _, ser_fn) in enumerate(_REGISTRY):
        if i in active:
            ser_fn(s)
    # Clean up internal tracking field
    s.pop("_active_protocols", None)


_discover()
