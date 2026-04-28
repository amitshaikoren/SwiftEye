"""
Velociraptor offline-collector ingestion adapter.

Handles two input shapes:
  - ZIP file (offline collector output): entries like
      artifact_Windows.System.Pslist/Windows.System.Pslist.csv
    Detected by ZIP magic bytes + at least one known artifact entry.
  - Bare CSV file: filename stem is the artifact name, e.g.
      Windows.System.Pslist.csv, Windows.Network.Netstat.csv

Two-pass dispatch:
  1. Parse Windows.System.Pslist first (if present) to build a
     pid→{image,user} map.
  2. Parse remaining artifacts with that map in context so Netstat rows
     can stamp the process image onto their src_entity, enabling node
     merging with pslist-sourced process nodes.

Unknown artifact names are silently skipped.
"""

from __future__ import annotations

import csv
import io
import logging
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from workspaces.forensic.parser.event import Event
from workspaces.forensic.parser.artifact_dissectors import (
    ARTIFACT_DISSECTORS,
    dispatch_artifact,
)
from workspaces.forensic.parser.artifact_dissectors.dissect_pslist import build_pid_map

from . import ForensicAdapter, register_adapter

logger = logging.getLogger("swifteye.forensic.velociraptor")

_ZIP_MAGIC = b"PK\x03\x04"

_KNOWN_ARTIFACTS = {
    "Windows.System.Pslist",
    "Windows.Network.Netstat",
}


@register_adapter
class VelociraptorAdapter(ForensicAdapter):
    name = "velociraptor"
    file_extensions = [".zip", ".csv"]
    source_type = "velociraptor"

    def can_handle(self, path: Path, header: bytes) -> bool:
        if header.startswith(_ZIP_MAGIC):
            return _zip_has_velociraptor_artifact(path)
        return path.suffix.lower() == ".csv" and path.stem in ARTIFACT_DISSECTORS

    def parse(self, path: Path, **opts) -> List[Event]:
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
        except OSError:
            magic = b""

        if magic.startswith(_ZIP_MAGIC):
            return _parse_zip(path, opts)
        return _parse_bare_csv(path, opts)


# ---------------------------------------------------------------------------
# ZIP path
# ---------------------------------------------------------------------------

def _zip_has_velociraptor_artifact(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for entry in zf.namelist():
                for artifact in _KNOWN_ARTIFACTS:
                    if artifact in entry:
                        return True
    except (zipfile.BadZipFile, OSError):
        pass
    return False


def _parse_zip(path: Path, opts: Dict[str, Any]) -> List[Event]:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            artifact_rows = _extract_artifacts(zf)
    except (zipfile.BadZipFile, OSError) as exc:
        logger.warning("Failed to open Velociraptor ZIP %s: %s", path.name, exc)
        return []
    computer = opts.get("computer") or _guess_computer_from_zip(path)
    return _dispatch_all(artifact_rows, computer)


def _extract_artifacts(zf: zipfile.ZipFile) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {}
    for entry_name in zf.namelist():
        artifact_name = _artifact_name_from_entry(entry_name)
        if artifact_name is None or artifact_name not in ARTIFACT_DISSECTORS:
            continue
        try:
            with zf.open(entry_name) as raw:
                rows = _read_csv(io.TextIOWrapper(raw, encoding="utf-8-sig"))
            result[artifact_name] = rows
        except Exception as exc:
            logger.warning("Failed to read artifact %s: %s", entry_name, exc)
    return result


def _artifact_name_from_entry(entry_name: str) -> Optional[str]:
    """Extract artifact name from a ZIP entry path.

    Velociraptor paths look like:
      artifact_Windows.System.Pslist/Windows.System.Pslist.csv
    or (with uploads/ prefix in some versions):
      uploads/artifact_Windows.System.Pslist/Windows.System.Pslist.csv
    """
    for part in Path(entry_name).parts:
        if part.startswith("artifact_"):
            return part[len("artifact_"):]
    p = Path(entry_name)
    if p.suffix.lower() == ".csv" and p.stem in ARTIFACT_DISSECTORS:
        return p.stem
    return None


def _guess_computer_from_zip(path: Path) -> str:
    """Best-effort hostname extraction from Velociraptor ZIP names.

    Velociraptor offline collectors produce ZIPs named like
    'Collection-DESKTOP-ABC123-2024-01-15T10-00-00Z.zip'.
    """
    parts = path.stem.split("-")
    if len(parts) >= 3 and parts[0].lower() == "collection":
        return parts[1]
    return ""


# ---------------------------------------------------------------------------
# Bare CSV path
# ---------------------------------------------------------------------------

def _parse_bare_csv(path: Path, opts: Dict[str, Any]) -> List[Event]:
    artifact_name = path.stem
    if artifact_name not in ARTIFACT_DISSECTORS:
        logger.warning("No dissector for artifact '%s'", artifact_name)
        return []
    try:
        with open(path, encoding="utf-8-sig") as f:
            rows = _read_csv(f)
    except OSError as exc:
        logger.warning("Failed to read %s: %s", path.name, exc)
        return []
    computer = opts.get("computer") or ""
    return _dispatch_all({artifact_name: rows}, computer)


# ---------------------------------------------------------------------------
# Shared two-pass dispatch
# ---------------------------------------------------------------------------

def _dispatch_all(
    artifact_rows: Dict[str, List[Dict[str, Any]]],
    computer: str,
) -> List[Event]:
    pslist_rows = artifact_rows.get("Windows.System.Pslist", [])
    pid_map = build_pid_map(pslist_rows)
    context: Dict[str, Any] = {"pid_map": pid_map, "computer": computer}

    events: List[Event] = []
    if pslist_rows:
        events.extend(dispatch_artifact("Windows.System.Pslist", pslist_rows, context))
    for artifact_name, rows in artifact_rows.items():
        if artifact_name == "Windows.System.Pslist":
            continue
        events.extend(dispatch_artifact(artifact_name, rows, context))
    return events


# ---------------------------------------------------------------------------
# CSV helper
# ---------------------------------------------------------------------------

def _read_csv(f) -> List[Dict[str, Any]]:
    return [dict(row) for row in csv.DictReader(f)]
