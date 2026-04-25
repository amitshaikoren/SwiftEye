"""
Sysmon EID 1 — ProcessCreate.

One new-process event. Produces an Event with:
  - action_type   : "process_create"
  - src_entity    : the parent process (if parent fields present)
  - dst_entity    : the new process
  - fields        : image, command line, hashes, integrity level, etc.
  - ts            : UtcTime from EventData (preferred) or SystemTime from header

Sysmon ProcessCreate fields referenced (not all are always present —
Sysmon config + agent version varies):
  UtcTime, ProcessGuid, ProcessId, Image, FileVersion, Description, Product,
  Company, OriginalFileName, CommandLine, CurrentDirectory, User, LogonGuid,
  LogonId, TerminalSessionId, IntegrityLevel, Hashes, ParentProcessGuid,
  ParentProcessId, ParentImage, ParentCommandLine, ParentUser.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from workspaces.forensic.parser.event import Event

from . import register_dissector


@register_dissector(1)
def dissect(raw: Dict[str, Any]) -> Optional[Event]:
    data: Dict[str, str] = raw.get("event_data") or {}

    dst = _process_entity(
        guid=data.get("ProcessGuid"),
        pid=data.get("ProcessId"),
        image=data.get("Image"),
        user=data.get("User"),
    )
    src = _process_entity(
        guid=data.get("ParentProcessGuid"),
        pid=data.get("ParentProcessId"),
        image=data.get("ParentImage"),
        user=data.get("ParentUser"),
    )

    fields: Dict[str, Any] = {
        "command_line":          data.get("CommandLine") or "",
        "parent_command_line":   data.get("ParentCommandLine") or "",
        "current_directory":     data.get("CurrentDirectory") or "",
        "integrity_level":       data.get("IntegrityLevel") or "",
        "hashes":                data.get("Hashes") or "",
        "file_version":          data.get("FileVersion") or "",
        "description":           data.get("Description") or "",
        "product":               data.get("Product") or "",
        "company":               data.get("Company") or "",
        "original_file_name":    data.get("OriginalFileName") or "",
        "logon_id":              data.get("LogonId") or "",
        "terminal_session_id":   data.get("TerminalSessionId") or "",
        "rule_name":             data.get("RuleName") or "",
    }

    ts = _pick_ts(data, raw)

    return Event(
        action_type="process_create",
        ts=ts,
        src_entity=src,
        dst_entity=dst,
        fields={k: v for k, v in fields.items() if v != ""},
        source={
            "eid": raw.get("eid"),
            "record_id": raw.get("record_id"),
            "computer": raw.get("computer"),
            "provider": raw.get("provider"),
        },
    )


def _process_entity(
    *,
    guid: Optional[str],
    pid: Optional[str],
    image: Optional[str],
    user: Optional[str],
) -> Dict[str, Any]:
    """Build a process-entity dict, dropping empties so downstream doesn't
    have to distinguish between missing and blank fields.

    Returns {} if nothing is known — the caller decides whether a missing
    parent entity is worth recording or not (EID 1 may have a bare-root
    process with no parent fields).
    """
    out: Dict[str, Any] = {"type": "process"}
    if guid:
        out["guid"] = guid
    if pid:
        try:
            out["pid"] = int(pid)
        except (TypeError, ValueError):
            out["pid"] = pid
    if image:
        out["image"] = image
    if user:
        out["user"] = user
    # If we know nothing about the process beyond "type", collapse to {}.
    return out if len(out) > 1 else {}


def _pick_ts(data: Dict[str, str], raw: Dict[str, Any]) -> Optional[datetime]:
    """Prefer Sysmon's EventData UtcTime (millisecond precision), fall back
    to the System-header TimeCreated the reader already parsed."""
    raw_utc = data.get("UtcTime")
    if raw_utc:
        parsed = _parse_sysmon_utc(raw_utc)
        if parsed is not None:
            return parsed
    ts = raw.get("time_created")
    return ts if isinstance(ts, datetime) else None


def _parse_sysmon_utc(value: str) -> Optional[datetime]:
    """Sysmon writes UtcTime as 'YYYY-MM-DD HH:MM:SS.mmm' (no timezone)."""
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
