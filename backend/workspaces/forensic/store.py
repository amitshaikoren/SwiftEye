"""
ForensicStore — viewer-layer state for the forensic workspace.

Holds the parsed event list and graph cache produced by `build_forensic_graph`.
Structurally mirrors network's CaptureStore but is forensic-specific and does
not share state with it.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from workspaces.forensic.parser.event import Event
from workspaces.forensic.analysis.action_aggregator import build_forensic_graph

logger = logging.getLogger("swifteye.forensic.store")


class ForensicStore:
    def __init__(self) -> None:
        self.events: List[Event] = []
        self.graph_cache: Dict[str, Any] = {}
        self.file_name: str = ""
        self.source_files: List[str] = []

    def load(self, events: List[Event], file_name: str, source_files: Optional[List[str]] = None) -> None:
        self.events = events
        self.file_name = file_name
        self.source_files = source_files or [file_name]
        self.graph_cache = {}

        t0 = time.time()
        self.graph_cache = build_forensic_graph(events)
        logger.info(
            f"Forensic '{file_name}' loaded: {len(events)} events → "
            f"{len(self.graph_cache['nodes'])} nodes, "
            f"{len(self.graph_cache['edges'])} edges in {time.time()-t0:.2f}s"
        )

    def clear(self) -> None:
        self.events = []
        self.graph_cache = {}
        self.file_name = ""
        self.source_files = []

    @property
    def is_loaded(self) -> bool:
        return bool(self.events)

    def get_events_for_edge(self, edge_key: str) -> List[Dict[str, Any]]:
        """Return the event list for an edge identified by 'src_id|dst_id'."""
        for edge in self.graph_cache.get("edges", []):
            if edge.get("id") == edge_key:
                return edge.get("events", [])
        return []


forensic_store = ForensicStore()
