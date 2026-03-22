"""
Auto-discovery registry for protocol field handlers.

Each module in this package defines three functions:
    init()                              → dict of initial session fields for this protocol
    accumulate(s, ex, is_fwd, source_type) → mutate session dict from one packet's extra
    serialize(s)                        → convert working fields (sets, etc.) to JSON-safe output

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
"""

import importlib
import pkgutil
from typing import Callable, Dict, Any, List, Tuple

# Each entry: (init_fn, accumulate_fn, serialize_fn)
_REGISTRY: List[Tuple[Callable, Callable, Callable]] = []


def _discover():
    """Import all sibling modules and collect their init/accumulate/serialize."""
    for _importer, modname, _ispkg in pkgutil.iter_modules(__path__):
        mod = importlib.import_module(f".{modname}", __name__)
        init_fn = getattr(mod, "init", None)
        acc_fn = getattr(mod, "accumulate", None)
        ser_fn = getattr(mod, "serialize", None)
        if init_fn and acc_fn and ser_fn:
            _REGISTRY.append((init_fn, acc_fn, ser_fn))


def all_init() -> Dict[str, Any]:
    """Merged initial fields from all registered protocols."""
    merged = {}
    for init_fn, _, _ in _REGISTRY:
        merged.update(init_fn())
    return merged


def all_accumulate(s: dict, ex: dict, is_fwd: bool, source_type: str = None):
    """Run all protocol accumulators on one packet."""
    for _, acc_fn, _ in _REGISTRY:
        acc_fn(s, ex, is_fwd, source_type)


def all_serialize(s: dict):
    """Run all protocol serializers on a completed session."""
    for _, _, ser_fn in _REGISTRY:
        ser_fn(s)


_discover()
