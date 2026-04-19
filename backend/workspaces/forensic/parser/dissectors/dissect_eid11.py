"""
Sysmon EID 11 — FileCreate.

A "process created or overwrote a file" event. Produces an Event with:
  - action_type   : "file_create"
  - src_entity    : the creating process (ProcessGuid/ProcessId/Image)
  - dst_entity    : the file (TargetFilename as path)
  - fields        : creation_utc_time (file-system creation stamp — distinct
                    from Event.ts which uses the Sysmon-observation UtcTime),
                    rule_name. Hashes sometimes appears on verbose Sysmon
                    configs — pulled opportunistically if present.
  - ts            : UtcTime from EventData (preferred) or SystemTime from header

Sysmon EID 11 EventData fields referenced:
  UtcTime, ProcessGuid, ProcessId, Image, User (optional on some configs),
  TargetFilename, CreationUtcTime, Hashes (optional), RuleName.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from workspaces.forensic.parser.event import Event

from . import register_dissector


@register_dissector(11)
def dissect(raw: Dict[str, Any]) -> Optional[Event]:
    data: Dict[str, str] = raw.get("event_data") or {}

    src = _process_entity(
        guid=data.get("ProcessGuid"),
        pid=data.get("ProcessId"),
        image=data.get("Image"),
        user=data.get("User"),
    )

    target = data.get("TargetFilename") or ""
    dst: Dict[str, Any] = {"type": "file", "path": target} if target else {}

    fields: Dict[str, Any] = {
        "creation_utc_time": data.get("CreationUtcTime") or "",
        "hashes":            data.get("Hashes") or "",
        "rule_name":         data.get("RuleName") or "",
    }
    fields = {k: v for k, v in fields.items() if v != ""}

    ts = _pick_ts(data, raw)

    return Event(
        action_type="file_create",
        ts=ts,
        src_entity=src,
        dst_entity=dst,
        fields=fields,
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
    return out if len(out) > 1 else {}


def _pick_ts(data: Dict[str, str], raw: Dict[str, Any]) -> Optional[datetime]:
    raw_utc = data.get("UtcTime")
    if raw_utc:
        try:
            return datetime.fromisoformat(raw_utc)
        except ValueError:
            pass
    ts = raw.get("time_created")
    return ts if isinstance(ts, datetime) else None
