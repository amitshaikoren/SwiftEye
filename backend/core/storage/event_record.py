"""
EventRecord — the planned universal normalized data record for Phase 2+.

This replaces PacketRecord as the canonical type flowing through the pipeline
once the SQLite backend is implemented. For now it is defined here as a
migration target. All adapters currently produce PacketRecord; Phase 2 will
map PacketRecord → EventRecord and store EventRecord in SQLite.

See HANDOFF.md §7 for the full ETL architecture design.
"""

from dataclasses import dataclass, field
from typing import Dict, Any


@dataclass
class EventRecord:
    """
    Universal normalized record. Every ingestion source maps to this type.

    PacketRecord is the pcap-specific type that maps to EventRecord with all
    pcap-specific fields preserved in extra{}. This is NOT a replacement for
    PacketRecord today — it is the Phase 2 migration target.
    """
    # ── Required: every source MUST provide ────────────────────────────
    timestamp: float = 0.0
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = ""

    # ── Common optional ─────────────────────────────────────────────────
    src_port: int = 0
    dst_port: int = 0
    src_mac: str = ""
    dst_mac: str = ""
    transport: str = ""
    bytes_total: int = 0
    ip_version: int = 4

    # ── Granularity: "packet" | "session" | "event" ────────────────────
    # Controls pipeline routing:
    #   "packet"  → run build_sessions() (pcap path)
    #   "session" → skip build_sessions(), each record IS a session (Zeek/netflow)
    #   "event"   → host-level event, future (Sysmon)
    granularity: str = "packet"

    # ── Source tracking ────────────────────────────────────────────────
    source_type: str = "pcap"  # "pcap" | "zeek" | "splunk" | "netflow" | ...

    # ── Everything else (source-specific fields from dissectors) ───────
    extra: Dict[str, Any] = field(default_factory=dict)
    # pcap: ttl, tcp_flags, seq_num, payload_preview, window_size, ...
    # zeek: duration, history, conn_state, uid, orig_bytes, resp_bytes, ...
    # splunk: action, app, user, severity, signature, bytes_in, bytes_out, ...
