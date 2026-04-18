"""
Normalized forensic event record.

All dissectors return `Event` instances. This is the boundary between
the parser layer (which reads raw records from a format-specific source —
EVTX, CSV, JSON, …) and the aggregator / schema-population layer that
Phase 5 introduces.

`src_entity` and `dst_entity` are loose dicts for Phase 4 (e.g.
`{"type": "process", "pid": 1234, "guid": "{...}"}`). Formal entity typing
arrives with Phase 5's schema population; keep the shape flexible until then.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass(slots=True)
class Event:
    """Single normalized forensic event, produced by a per-EID dissector."""
    # What happened — verb-ish label. E.g. "process_create", "network_connect".
    action_type: str = ""

    # When it happened (UTC). Sysmon's <UtcTime> EventData field when present,
    # otherwise the System/TimeCreated attribute.
    ts: Optional[datetime] = None

    # Actor and target. Loose dicts until Phase 5 formalises entity types.
    src_entity: Dict[str, Any] = field(default_factory=dict)
    dst_entity: Dict[str, Any] = field(default_factory=dict)

    # Per-EID payload (image path, command line, registry key, file size, …).
    # Everything the dissector extracted that isn't part of src/dst identity.
    fields: Dict[str, Any] = field(default_factory=dict)

    # Raw provenance — useful for debugging and for future "jump to raw record"
    # UI affordances. The source-record-id (EVTX EventRecordID) and the EID
    # are enough to locate the original log entry.
    source: Dict[str, Any] = field(default_factory=dict)
