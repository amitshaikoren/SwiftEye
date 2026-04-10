"""
MemoryBackend — in-memory storage backend with dict indexes for O(1) lookups.

Holds REFERENCES to store.packets and store.sessions (not copies).
Indexes are rebuilt on each load() call.
"""

import logging
from ipaddress import IPv4Network, IPv4Address
from typing import List, Dict, Optional, Tuple, Set, TYPE_CHECKING
from collections import defaultdict

from storage.backend import StorageBackend
from storage.serializers import serialize_packet

if TYPE_CHECKING:
    from parser.packet import PacketRecord

logger = logging.getLogger("swifteye.storage.memory")


# ── Canonical session↔edge matching ─────────────────────────────────────
# Single source of truth. Used by MemoryBackend.get_sessions_for_edge()
# and by build_analysis_graph's _ses_by_pair. Frontend has a mirror copy
# in sessionMatch.js for fast client-side filtering.

def _ip_matches_endpoint(ip: str, endpoint: str) -> bool:
    """Check if a raw IP matches an edge endpoint.

    Handles:
      - Direct IP match ("10.0.0.1" == "10.0.0.1")
      - Subnet CIDR ("10.0.0.1" in "10.0.0.0/24")
      - MAC-split node IDs ("10.0.0.1::aa:bb:cc" → compare "10.0.0.1")
    """
    if ip == endpoint:
        return True
    # MAC-split: "10.0.0.1::aa:bb:cc:dd:ee:ff" → strip MAC suffix
    if "::" in endpoint and not endpoint.startswith("::"):
        base_ip = endpoint.split("::")[0]
        if ip == base_ip:
            return True
    # Subnet CIDR: "192.168.1.0/24"
    if "/" in endpoint and ":" not in ip:
        try:
            return IPv4Address(ip) in IPv4Network(endpoint, strict=False)
        except (ValueError, TypeError):
            pass
    return False


def _protocol_matches(session_protocol: str, session_transport: str,
                      edge_protocol: str) -> bool:
    """Check if a session's protocol matches an edge's protocol.

    Matches when:
      - session.protocol == edge_protocol (normal case, e.g. both "TLS")
      - session.transport == edge_protocol (session stayed as "TCP" but
        edge is "TCP" for handshake packets)
    """
    return session_protocol == edge_protocol or session_transport == edge_protocol


def _session_matches_edge(session: dict, edge_src: str, edge_dst: str,
                          edge_protocol: str) -> bool:
    """Canonical check: does this session belong to this edge?"""
    s_src = session.get("src_ip", "")
    s_dst = session.get("dst_ip", "")
    s_proto = session.get("protocol", "")
    s_transport = session.get("transport", "")

    if not _protocol_matches(s_proto, s_transport, edge_protocol):
        return False

    # Bidirectional IP match: session (src,dst) can be in either order
    # relative to edge (src,dst) because session IPs are sorted.
    return (
        (_ip_matches_endpoint(s_src, edge_src) and _ip_matches_endpoint(s_dst, edge_dst)) or
        (_ip_matches_endpoint(s_src, edge_dst) and _ip_matches_endpoint(s_dst, edge_src))
    )


class MemoryBackend(StorageBackend):
    """
    In-memory storage backend with dict indexes for O(1) lookups.

    Index structures:
      _by_session_key: session_key → [packet_list_indices]
      _sessions_by_id: session_id → session_dict
      _session_keys_by_15s_bucket: int_bucket → {session_keys}
    """

    def __init__(self):
        self._packets: List["PacketRecord"] = []
        self._sessions: List[dict] = []
        self._by_session_key: Dict[str, List[int]] = {}
        self._sessions_by_id: Dict[str, dict] = {}
        self._session_keys_by_15s_bucket: Dict[int, Set[str]] = defaultdict(set)
        self._min_timestamp: float = 0.0
        self._loaded: bool = False

    def load(self, packets: List["PacketRecord"], sessions: List[dict]) -> None:
        self.clear()
        self._packets = packets
        self._sessions = sessions

        # Build packet index: session_key → list of indices
        for i, pkt in enumerate(packets):
            key = pkt.session_key
            if key not in self._by_session_key:
                self._by_session_key[key] = []
            self._by_session_key[key].append(i)

        # Build session indexes
        for s in sessions:
            sid = s.get("id", "")
            if sid:
                self._sessions_by_id[sid] = s

        # Build time-bucket index for session-key lookup by time range
        # Bucket size: 15 seconds (matches build_time_buckets default)
        if packets:
            self._min_timestamp = packets[0].timestamp
            for pkt in packets:
                bucket = int((pkt.timestamp - self._min_timestamp) / 15)
                self._session_keys_by_15s_bucket[bucket].add(pkt.session_key)

        self._loaded = True
        logger.info(
            "MemoryBackend indexed %d packets, %d sessions, %d unique session keys",
            len(packets), len(sessions), len(self._by_session_key),
        )

    def clear(self) -> None:
        self._packets = []
        self._sessions = []
        self._by_session_key = {}
        self._sessions_by_id = {}
        self._session_keys_by_15s_bucket = defaultdict(set)
        self._min_timestamp = 0.0
        self._loaded = False

    def get_packets_for_session(
        self, session_id: str, limit: int = 1000, offset: int = 0
    ) -> List[dict]:
        indices = self._by_session_key.get(session_id, [])
        page = indices[offset: offset + limit]
        return [serialize_packet(self._packets[i]) for i in page]

    def get_session(self, session_id: str) -> Optional[dict]:
        return self._sessions_by_id.get(session_id)

    def get_sessions(
        self,
        sort_by: str = "bytes",
        limit: int = 200,
        offset: int = 0,
        search: str = "",
        time_start: Optional[float] = None,
        time_end: Optional[float] = None,
    ) -> Tuple[List[dict], int]:
        sessions = self._sessions

        # Time filter: use bucket index
        if time_start is not None and time_end is not None:
            active_keys = self.get_session_keys_for_time_range(time_start, time_end)
            sessions = [s for s in sessions if s.get("id") in active_keys]

        # Search filter
        if search:
            q = search.lower()
            sessions = [
                s for s in sessions
                if q in s.get("src_ip", "").lower()
                or q in s.get("dst_ip", "").lower()
                or q in s.get("protocol", "").lower()
                or q in str(s.get("src_port", ""))
                or q in str(s.get("dst_port", ""))
            ]

        # Sort
        if sort_by == "bytes":
            sessions = sorted(sessions, key=lambda s: s.get("total_bytes", 0), reverse=True)
        elif sort_by == "packets":
            sessions = sorted(sessions, key=lambda s: s.get("packet_count", 0), reverse=True)
        elif sort_by == "duration":
            sessions = sorted(sessions, key=lambda s: s.get("duration", 0), reverse=True)
        else:  # "time" — chronological
            sessions = sorted(sessions, key=lambda s: s.get("start_time", 0))

        total = len(sessions)
        return sessions[offset: offset + limit], total

    def get_session_keys_for_time_range(
        self, time_start: float, time_end: float
    ) -> Set[str]:
        if not self._packets:
            return set()
        start_bucket = max(0, int((time_start - self._min_timestamp) / 15))
        end_bucket = int((time_end - self._min_timestamp) / 15)
        keys: Set[str] = set()
        for b in range(start_bucket, end_bucket + 1):
            keys.update(self._session_keys_by_15s_bucket.get(b, set()))
        return keys

    def get_sessions_for_edge(
        self,
        edge_src: str,
        edge_dst: str,
        edge_protocol: str,
        sort_by: str = "bytes",
        limit: int = 500,
    ) -> Tuple[List[dict], int]:
        matched = []
        for s in self._sessions:
            if not _session_matches_edge(s, edge_src, edge_dst, edge_protocol):
                continue
            matched.append(s)

        if sort_by == "packets":
            matched.sort(key=lambda s: s.get("packet_count", 0), reverse=True)
        elif sort_by == "duration":
            matched.sort(key=lambda s: s.get("duration", 0), reverse=True)
        elif sort_by == "time":
            matched.sort(key=lambda s: s.get("start_time", 0))
        else:  # "bytes"
            matched.sort(key=lambda s: s.get("total_bytes", 0), reverse=True)

        total = len(matched)
        return matched[:limit], total

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def packet_count(self) -> int:
        return len(self._packets)

    @property
    def session_count(self) -> int:
        return len(self._sessions)
