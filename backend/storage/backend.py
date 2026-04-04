"""
StorageBackend ABC — the contract for all storage implementations.

Phase 1: MemoryBackend (in-memory indexes on existing lists)
Phase 2: SQLiteBackend (embedded DB, streaming ingest)
Phase 3: PostgresBackend (multi-user, TimescaleDB)
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Tuple, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from parser.packet import PacketRecord


class StorageBackend(ABC):
    """
    Abstract storage backend for SwiftEye captured data.

    This ABC covers only the hot-path operations that were O(n) scans.
    filter_packets() and build_graph() are NOT in this contract for Phase 1 —
    they remain as Python functions operating on store.packets directly.
    Phase 2 will add a sql_filter() optional method when SQL translation is needed.
    """

    @abstractmethod
    def load(self, packets: List["PacketRecord"], sessions: List[dict]) -> None:
        """
        Index a loaded capture. Called once per capture load, after
        build_sessions() has run. packets and sessions are the same
        list objects that CaptureStore holds — backend stores references,
        not copies. Phase 2 will change this to write to DB instead.
        """
        ...

    @abstractmethod
    def clear(self) -> None:
        """Reset all indexes. Called before loading a new capture."""
        ...

    @abstractmethod
    def get_packets_for_session(
        self,
        session_id: str,
        limit: int = 1000,
        offset: int = 0,
    ) -> List[dict]:
        """
        Return serialized packet dicts for a session. Paginated.
        Returns [] if session_id not found.
        Each dict has the same shape as the old CaptureStore._serialize_packet().
        """
        ...

    @abstractmethod
    def get_session(self, session_id: str) -> Optional[dict]:
        """Return a single session dict by ID, or None if not found."""
        ...

    @abstractmethod
    def get_sessions(
        self,
        sort_by: str = "time",
        limit: int = 200,
        offset: int = 0,
        search: str = "",
        time_start: Optional[float] = None,
        time_end: Optional[float] = None,
    ) -> Tuple[List[dict], int]:
        """
        Return (page_of_session_dicts, total_matching_count).
        sort_by: "time" | "bytes" | "packets" | "duration"
        search: substring match against src_ip, dst_ip, protocol, ports.
        time_start/time_end: Unix seconds. None = no time filter.
        """
        ...

    @abstractmethod
    def get_session_keys_for_time_range(
        self,
        time_start: float,
        time_end: float,
    ) -> Set[str]:
        """
        Return all session_keys that had at least one packet in [time_start, time_end].
        Used for time-range scoping in the sessions list.
        Phase 2: SQL query with timestamp index.
        """
        ...

    @property
    @abstractmethod
    def is_loaded(self) -> bool:
        """True if a capture has been loaded."""
        ...

    @property
    @abstractmethod
    def packet_count(self) -> int:
        """Total number of packets in the loaded capture."""
        ...

    @property
    @abstractmethod
    def session_count(self) -> int:
        """Total number of sessions in the loaded capture."""
        ...
