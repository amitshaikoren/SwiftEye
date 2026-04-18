"""
Forensic workspace schema — Phase 3 skeleton.

Empty catalog. Phase 5 declares the real forensic node/edge types
(process, file, registry, endpoint, user, host + created, connected,
wrote, set_value, terminated) once EVTX ingestion and the action
aggregator land.

Declared separately from the workspace registration so future phases
populate this file in one place without touching `__init__.py`.
"""

from __future__ import annotations

from core.schema import WorkspaceSchema


FORENSIC_SCHEMA = WorkspaceSchema(workspace="forensic")
