"""
Storage backend abstraction for SwiftEye.

Phase 1: MemoryBackend — in-memory lists with dict indexes for O(1) lookups.
Phase 2: SQLiteBackend — embedded DB, zero-config, persistent workspace.
Phase 3: PostgresBackend — multi-user, TimescaleDB, Neo4j secondary.
"""

from core.storage.backend import StorageBackend
from core.storage.memory import MemoryBackend
from core.storage.event_record import EventRecord

__all__ = ["StorageBackend", "MemoryBackend", "EventRecord"]
