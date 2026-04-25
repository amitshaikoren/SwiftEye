"""
EVTX ingestion adapter.

Wraps `evtx_reader.read_evtx()` and routes each raw record through the
per-EID dissector table. Output is a list of normalized `Event`s —
records whose EID has no registered dissector are silently skipped (same
pattern network uses for unknown protocols).
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from workspaces.forensic.parser.event import Event
from workspaces.forensic.parser.evtx_reader import read_evtx
from workspaces.forensic.parser.dissectors.dispatch import dispatch

from . import ForensicAdapter, register_adapter

# EVTX binary file magic — ASCII "ElfFile" + NUL.
_EVTX_MAGIC = b"ElfFile\x00"


@register_adapter
class EvtxAdapter(ForensicAdapter):
    name = "evtx"
    file_extensions = [".evtx"]
    source_type = "evtx"

    def can_handle(self, path: Path, header: bytes) -> bool:
        if path.suffix.lower() in self.file_extensions:
            return True
        return header.startswith(_EVTX_MAGIC)

    def parse(self, path: Path, **opts) -> List[Event]:
        max_records = opts.get("max_records", 5_000_000)
        raws = read_evtx(str(path), max_records=max_records)
        events: List[Event] = []
        for raw in raws:
            evt = dispatch(raw)
            if evt is not None:
                events.append(evt)
        return events
