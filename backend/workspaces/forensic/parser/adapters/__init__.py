"""
Forensic workspace ingestion adapter registry.

Mirrors `workspaces/network/parser/adapters/` but returns `List[Event]`
instead of `List[PacketRecord]`. The two registries are deliberately
kept separate for Phase 4 — each workspace owns its own ingestion shape.
A later phase can promote a generic adapter abstraction into `core/` once
the duplication is concrete (reusability ledger tracks this).

Adapters are auto-imported at the bottom of this module so their
`@register_adapter` decorators fire at startup.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional, Type

from workspaces.forensic.parser.event import Event

logger = logging.getLogger("swifteye.forensic.adapters")

# ── Registry ─────────────────────────────────────────────────────────────

ADAPTERS: List[Type["ForensicAdapter"]] = []


class ForensicAdapter:
    """Base class for forensic ingestion adapters.

    Each adapter reads one source format (EVTX, CSV export, JSON export, …)
    and returns a list of normalized `Event` records — one per dissected
    log entry. Dispatch routing lives inside the adapter's `parse()` impl;
    the adapter is what glues a reader to the per-EID dissector table.
    """

    name: str = ""
    file_extensions: List[str] = []
    source_type: str = ""

    def can_handle(self, path: Path, header: bytes) -> bool:
        raise NotImplementedError

    def parse(self, path: Path, **opts) -> List[Event]:
        raise NotImplementedError


def register_adapter(cls: Type[ForensicAdapter]) -> Type[ForensicAdapter]:
    """Decorator to register a forensic ingestion adapter."""
    ADAPTERS.append(cls)
    logger.debug("Registered forensic adapter: %s", cls.name)
    return cls


def find_adapter_by_name(name: str) -> Optional[ForensicAdapter]:
    for cls in ADAPTERS:
        if cls.name == name:
            return cls()
    return None


def detect_adapter(path: Path) -> Optional[ForensicAdapter]:
    """Detect which adapter handles a file via extension + header sniffing."""
    try:
        with open(path, "rb") as f:
            header = f.read(64)
    except OSError:
        header = b""

    for cls in ADAPTERS:
        adapter = cls()
        try:
            if adapter.can_handle(path, header):
                logger.info("Detected forensic adapter: %s for %s", adapter.name, path.name)
                return adapter
        except Exception as exc:  # pragma: no cover — defensive
            logger.debug("Adapter %s failed detection: %s", adapter.name, exc)
    return None


# ── Auto-import adapters so they self-register ───────────────────────────
from . import evtx_adapter  # noqa: E402, F401
