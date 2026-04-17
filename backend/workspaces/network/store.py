"""
CaptureStore — in-memory state for the currently loaded capture.

Holds viewer-layer data (sessions, stats, time buckets, subnets, graph cache).
Does NOT run plugins — that's the server's orchestration concern.
"""

import time
import uuid
import logging
from typing import Optional

from fastapi import HTTPException

from workspaces.network.parser.packet import PacketRecord
from workspaces.network.analysis import (
    build_time_buckets, build_graph, build_analysis_graph,
    filter_packets, build_sessions, compute_global_stats, get_subnets,
)
from core.storage.memory import MemoryBackend
from core.storage.serializers import _payload_hexdump, _payload_hex, _payload_ascii, _payload_entropy

logger = logging.getLogger("swifteye.store")


# ── Capture State (in-memory, single-user) ───────────────────────────────

class CaptureStore:
    """
    Holds the current loaded capture and its core viewer data.

    This is strictly viewer-layer: sessions, stats, time buckets, subnets.
    It does NOT run plugins — that's the server's orchestration concern.
    Removing all plugins should leave CaptureStore fully functional.
    """

    def __init__(self):
        self.capture_id: Optional[str] = None
        self.file_name: str = ""
        self.source_files: list[str] = []   # all uploaded filenames (multi-pcap)
        self.packets: list[PacketRecord] = []
        self.sessions: list[dict] = []
        self.stats: dict = {}
        self.time_buckets: list[dict] = []
        self.protocols: set[str] = set()
        self.subnets: dict = {}
        self.metadata_map: dict = {}       # IP → researcher-provided metadata
        self.annotations: dict = {}        # uuid → {id, x, y, label, color, node_id?, edge_id?, created_at}
        self.synthetic: dict = {}          # uuid → {id, type:"node"|"edge", ...fields}
        self.graph_cache: dict = {}        # last built graph: {"nodes": [...], "edges": [...]}
        self.analysis_graph = None         # persistent NetworkX graph for query engine
        self.alerts: list = []                                     # AlertRecord dicts from detectors
        self.investigation: dict = {"markdown": "", "images": {}}  # investigation notebook
        self.backend: MemoryBackend = MemoryBackend()

    def load(self, packets: list[PacketRecord], file_name: str, source_files: list[str] = None):
        """
        Load a new capture, computing all core viewer data.

        Does NOT run plugins — call run_plugins() separately after this.
        """
        self.capture_id = str(uuid.uuid4())[:8]
        self.file_name = file_name
        self.source_files = source_files or [file_name]
        self.packets = packets

        # Clear per-capture state that is specific to the previous capture.
        self.annotations = {}
        self.synthetic = {}
        self.metadata_map = {}
        self.graph_cache = {}
        self.alerts = []
        self.investigation = {"markdown": "", "images": {}}

        logger.info(f"Building sessions...")
        t0 = time.time()
        self.sessions = build_sessions(packets)
        logger.info(f"  {len(self.sessions)} sessions in {time.time()-t0:.2f}s")

        logger.info(f"Computing stats...")
        t0 = time.time()
        self.stats = compute_global_stats(packets, self.sessions)
        logger.info(f"  Stats computed in {time.time()-t0:.2f}s")

        logger.info(f"Building time buckets...")
        t0 = time.time()
        self.time_buckets = build_time_buckets(packets)
        logger.info(f"  {len(self.time_buckets)} buckets in {time.time()-t0:.2f}s")

        self.protocols = {p.protocol for p in packets if p.protocol and p.protocol.strip()}
        self.subnets = get_subnets(packets)

        logger.info(f"Building analysis graph...")
        t0 = time.time()
        self.analysis_graph = build_analysis_graph(packets, self.sessions)
        logger.info(f"  Analysis graph in {time.time()-t0:.2f}s")

        logger.info("Building storage indexes...")
        t0 = time.time()
        self.backend.load(self.packets, self.sessions)
        logger.info(f"  Indexes in {time.time()-t0:.2f}s")

        logger.info(f"Capture '{file_name}' loaded: {len(packets)} packets, "
                     f"{len(self.sessions)} sessions, {len(self.protocols)} protocols")

    def get_packets_for_session(self, session_id: str, limit: int = 1000, offset: int = 0) -> list[dict]:
        """Get packets for a session. O(1) indexed lookup via MemoryBackend."""
        return self.backend.get_packets_for_session(session_id, limit=limit, offset=offset)

    @property
    def is_loaded(self) -> bool:
        return len(self.packets) > 0


store = CaptureStore()


def _require_capture():
    """Raise 404 if no capture is loaded. Used by route handlers."""
    if not store.is_loaded:
        raise HTTPException(404, "No capture loaded. Upload a pcap first.")
