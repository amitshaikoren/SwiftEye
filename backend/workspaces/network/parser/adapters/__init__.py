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
from typing import Dict, List, Optional, Type

from workspaces.network.parser.packet import PacketRecord

logger = logging.getLogger("swifteye.adapters")

# ── Registry ─────────────────────────────────────────────────────────────

ADAPTERS: List[Type["IngestionAdapter"]] = []


class IngestionAdapter:
    """Base class for all ingestion adapters.

    Schema negotiation hooks
    ------------------------
    Subclasses that support schema negotiation must override:
      declared_fields  — list of SchemaField describing expected columns
      get_header_columns(path) → List[str]  — read column names from file header
      get_raw_rows(path)       → List[Dict] — read all rows as dicts
      _rows_to_packets(rows)   → List[PacketRecord]

    parse() is implemented here as get_raw_rows() + _rows_to_packets().
    parse_with_mapping() applies a column-rename mapping before _rows_to_packets().

    Adapters that do NOT support schema negotiation (e.g. PcapAdapter) can
    leave declared_fields empty and override parse() directly — the base
    parse_with_mapping() will fall through to parse() unchanged.
    """
    name: str = ""
    file_extensions: List[str] = []
    granularity: str = "packet"  # "packet" or "session"
    source_type: str = ""

    # Override in subclasses to declare the columns this adapter expects.
    # Import SchemaField lazily to avoid circular imports at module load time.
    declared_fields: list = []  # List[SchemaField]

    def can_handle(self, path: Path, header: bytes) -> bool:
        raise NotImplementedError

    # ── Schema negotiation hooks (override in text-format adapters) ───────

    def get_header_columns(self, path: Path) -> List[str]:
        """Return column names from the file header without reading all rows.

        Override in subclasses. Default implementation reads all rows and
        returns keys from the first row dict (expensive for large files but
        correct as a fallback).
        """
        rows = self.get_raw_rows(path)
        return list(rows[0].keys()) if rows else []

    def get_raw_rows(self, path: Path) -> List[Dict[str, str]]:
        """Return all rows as dicts. Override in subclasses."""
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement get_raw_rows(). "
            "Either implement get_raw_rows() + _rows_to_packets(), or keep "
            "parse() as a self-contained override and leave declared_fields empty."
        )

    def _rows_to_packets(self, rows: List[Dict[str, str]]) -> List[PacketRecord]:
        """Convert row dicts to PacketRecords. Override in subclasses."""
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement _rows_to_packets()."
        )

    def parse(self, path: Path, **opts) -> List[PacketRecord]:
        """Default: get_raw_rows() → _rows_to_packets().

        Adapters with schema negotiation support get this for free.
        Adapters that override parse() directly (e.g. PcapAdapter) keep
        their existing behaviour — schema negotiation simply won't apply.
        """
        rows = self.get_raw_rows(path)
        return self._rows_to_packets(rows)

    def parse_with_mapping(self, path: Path, mapping: Dict[str, str]) -> List[PacketRecord]:
        """Parse with a user-confirmed column rename mapping.

        mapping = {actual_col_in_file: expected_field_name_adapter_uses}

        Calls get_raw_rows(), renames keys per mapping, then _rows_to_packets().
        Falls back to plain parse() if declared_fields is empty (no schema
        negotiation declared for this adapter).
        """
        if not self.declared_fields:
            return self.parse(path)
        rows = self.get_raw_rows(path)
        remapped = [{mapping.get(k, k): v for k, v in row.items()} for row in rows]
        return self._rows_to_packets(remapped)


def register_adapter(cls: Type[IngestionAdapter]) -> Type[IngestionAdapter]:
    """Decorator to register an ingestion adapter."""
    ADAPTERS.append(cls)
    logger.debug("Registered adapter: %s", cls.name)
    return cls


def find_adapter_by_name(name: str) -> Optional[IngestionAdapter]:
    """Return an instantiated adapter whose name matches exactly, or None."""
    for adapter_cls in ADAPTERS:
        if adapter_cls.name == name:
            return adapter_cls()
    return None


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
from . import tshark          # noqa: E402, F401  — registers all tshark CSV adapters
