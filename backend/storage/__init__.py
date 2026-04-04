"""
Storage backend abstraction for SwiftEye.

Phase 1: MemoryBackend — in-memory lists with dict indexes for O(1) lookups.
Phase 2: SQLiteBackend — embedded DB, zero-config, persistent workspace.
Phase 3: PostgresBackend — multi-user, TimescaleDB, Neo4j secondary.
"""

from storage.backend import StorageBackend
from storage.memory import MemoryBackend
from storage.event_record import EventRecord

__all__ = ["StorageBackend", "MemoryBackend", "EventRecord"]
