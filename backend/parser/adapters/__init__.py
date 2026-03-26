"""
Ingestion adapter registry for SwiftEye.

Each adapter reads one file format and produces List[PacketRecord].
Adapters are registered via @register_adapter and auto-detected by
file extension and header sniffing.

To add a new adapter:
  1. Create a new file in the appropriate subdirectory
     (e.g. zeek/mylog.py for Zeek logs, or a new subdir for other sources)
  2. Subclass IngestionAdapter
  3. Decorate with @register_adapter
  4. Import in the subdirectory's __init__.py
"""

import logging
from pathlib import Path
from typing import List, Optional, Type

from parser.packet import PacketRecord

logger = logging.getLogger("swifteye.adapters")

# ── Registry ─────────────────────────────────────────────────────────────

ADAPTERS: List[Type["IngestionAdapter"]] = []


class IngestionAdapter:
    """Base class for all ingestion adapters."""
    name: str = ""
    file_extensions: List[str] = []
    granularity: str = "packet"  # "packet" or "session"
    source_type: str = ""

    def can_handle(self, path: Path, header: bytes) -> bool:
        raise NotImplementedError

    def parse(self, path: Path, **opts) -> List[PacketRecord]:
        raise NotImplementedError


def register_adapter(cls: Type[IngestionAdapter]) -> Type[IngestionAdapter]:
    """Decorator to register an ingestion adapter."""
    ADAPTERS.append(cls)
    logger.debug("Registered adapter: %s", cls.name)
    return cls


def detect_adapter(path: Path) -> Optional[IngestionAdapter]:
    """Detect which adapter can handle a file by extension + header sniffing."""
    try:
        with open(path, "rb") as f:
            header = f.read(8192)
    except Exception:
        header = b""

    # Try each registered adapter
    for adapter_cls in ADAPTERS:
        adapter = adapter_cls()
        try:
            if adapter.can_handle(path, header):
                logger.info("Detected adapter: %s for %s", adapter.name, path.name)
                return adapter
        except Exception as e:
            logger.debug("Adapter %s failed detection for %s: %s", adapter.name, path.name, e)

    return None


# ── Import adapters so they register themselves ──────────────────────────
from . import pcap_adapter  # noqa: E402, F401
from . import zeek            # noqa: E402, F401  — registers all Zeek log adapters
