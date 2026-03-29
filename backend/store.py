"""
CaptureStore — in-memory state for the currently loaded capture.

Holds viewer-layer data (sessions, stats, time buckets, subnets, graph cache).
Does NOT run plugins — that's the server's orchestration concern.
"""

import math
import time
import uuid
import logging
from typing import Optional
from collections import Counter

from fastapi import HTTPException

from parser.packet import PacketRecord
from data import (
    build_time_buckets, build_graph, build_analysis_graph,
    filter_packets, build_sessions, compute_global_stats, get_subnets,
)

logger = logging.getLogger("swifteye.store")


# ── Payload preview helpers ─────────────────────────────────────────────

def _payload_hexdump(data: bytes) -> str:
    """
    Format raw bytes as a unified Wireshark-style hex dump.
    Each row: offset  hex-bytes (padded to 16)  ascii
    Example:  0000  16 03 01 00 f1 01 00 00  .......
    Returned as a single string with newline-separated rows.
    The frontend renders this in a single <pre> block — no column splitting needed.
    """
    if not data:
        return ""
    rows = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part  = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"{i:04x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(rows)


# Keep old names as aliases for any callers — both now point to the unified dump
def _payload_hex(data: bytes) -> str:
    return _payload_hexdump(data)

def _payload_ascii(data: bytes) -> str:
    return ""  # ASCII is now embedded in the hex dump rows; no longer served separately


def _payload_entropy(data: bytes) -> dict:
    """
    Compute Shannon entropy of payload bytes and classify it.

    Returns {value, label, min_bytes} or empty dict if too few bytes.
    Minimum 16 bytes for a meaningful reading.
    """
    if not data or len(data) < 16:
        return {}
    counts = Counter(data)
    length = len(data)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    entropy = round(entropy, 2)

    if entropy < 1.0:
        label = "Structured/repetitive"
    elif entropy < 3.5:
        label = "Low entropy (structured binary)"
    elif entropy < 5.0:
        label = "Text/markup"
    elif entropy < 6.5:
        label = "Mixed/encoded"
    elif entropy < 7.5:
        label = "High entropy (compressed)"
    else:
        label = "Likely encrypted/compressed"

    return {"value": entropy, "label": label, "byte_count": length}


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
        self.investigation: dict = {"markdown": "", "images": {}}  # investigation notebook

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

        logger.info(f"Capture '{file_name}' loaded: {len(packets)} packets, "
                     f"{len(self.sessions)} sessions, {len(self.protocols)} protocols")

    def get_packets_for_session(self, session_id: str, limit: int = 200) -> list[dict]:
        """Get packets belonging to a specific session, with full detail."""
        session = None
        for s in self.sessions:
            if s["id"] == session_id:
                session = s
                break
        if not session:
            return []

        result = []
        count = 0
        for pkt in self.packets:
            if pkt.session_key == session_id:
                result.append({
                    "timestamp": pkt.timestamp,
                    "src_ip": pkt.src_ip,
                    "dst_ip": pkt.dst_ip,
                    "src_port": pkt.src_port,
                    "dst_port": pkt.dst_port,
                    "protocol": pkt.protocol,
                    "transport": pkt.transport,
                    "length": pkt.orig_len,
                    "payload_len": pkt.payload_len,
                    "ttl": pkt.ttl,
                    "tcp_flags_str": pkt.tcp_flags_str,
                    "tcp_flags_list": pkt.tcp_flags_list,
                    "seq_num": pkt.seq_num,
                    "ack_num": pkt.ack_num,
                    "window_size": pkt.window_size,
                    "tcp_options": pkt.tcp_options,
                    # IP header fields
                    "ip_version": pkt.ip_version,
                    "dscp": pkt.dscp,
                    "ecn": pkt.ecn,
                    "ip_id": pkt.ip_id,
                    "ip_flags": pkt.ip_flags,
                    "frag_offset": pkt.frag_offset,
                    "ip_checksum": pkt.ip_checksum,
                    "ip6_flow_label": pkt.ip6_flow_label,
                    "tcp_checksum": pkt.tcp_checksum,
                    "extra": pkt.extra,
                    "payload_hex":   _payload_hex(pkt.payload_preview),
                    "payload_ascii": _payload_ascii(pkt.payload_preview),
                    "payload_bytes": pkt.payload_preview.hex() if pkt.payload_preview else "",
                    "payload_entropy": _payload_entropy(pkt.payload_preview),
                })
                count += 1
                if count >= limit:
                    break
        return result

    @property
    def is_loaded(self) -> bool:
        return len(self.packets) > 0


store = CaptureStore()


def _require_capture():
    """Raise 404 if no capture is loaded. Used by route handlers."""
    if not store.is_loaded:
        raise HTTPException(404, "No capture loaded. Upload a pcap first.")
