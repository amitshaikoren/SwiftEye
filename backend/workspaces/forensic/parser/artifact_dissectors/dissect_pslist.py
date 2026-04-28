"""
Velociraptor Windows.System.Pslist artifact dissector.

One row = one running process at collection time. Produces a
"process_create" Event (parent → child) so the aggregator builds the
process tree. PPid=0 or unknown parents get a synthetic System root entity.

Also exposes build_pid_map() so VelociraptorAdapter can resolve pid→image
when dissecting other artifacts (e.g. Netstat).

CSV columns consumed: Pid, PPid, Name, Exe, CommandLine, CreateTime,
User (case-insensitive; unmapped extras are silently ignored).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from workspaces.forensic.parser.event import Event

from . import register_artifact_dissector

_ARTIFACT = "Windows.System.Pslist"

_SYSTEM_ENTITY: Dict[str, Any] = {"type": "process", "pid": 0, "image": "System"}


def build_pid_map(rows: List[Dict[str, Any]]) -> Dict[int, Dict[str, Any]]:
    """Return {pid: {image, user}} from pslist rows.

    Used by VelociraptorAdapter to build context for other artifact dissectors.
    """
    pid_map: Dict[int, Dict[str, Any]] = {}
    for row in rows:
        r = _normalize(row)
        pid = _intish(r.get("pid"))
        if pid is None:
            continue
        entry: Dict[str, Any] = {}
        image = r.get("exe") or r.get("name") or ""
        if image:
            entry["image"] = image
        user = r.get("user") or r.get("username") or ""
        if user:
            entry["user"] = user
        pid_map[pid] = entry
    return pid_map


@register_artifact_dissector(_ARTIFACT)
def dissect(row: Dict[str, Any], context: Dict[str, Any]) -> Optional[Event]:
    r = _normalize(row)

    pid  = _intish(r.get("pid"))
    ppid = _intish(r.get("ppid"))
    exe  = r.get("exe") or r.get("name") or ""
    user = r.get("user") or r.get("username") or ""
    cmdline  = r.get("commandline") or ""
    ts       = _parse_ts(r.get("createtime") or "")
    computer = context.get("computer") or ""

    if pid is None:
        return None

    dst: Dict[str, Any] = {"type": "process", "pid": pid}
    if exe:
        dst["image"] = exe
    if user:
        dst["user"] = user
    if computer:
        dst["computer"] = computer

    if ppid is not None and ppid > 0:
        pid_map: Dict[int, Dict[str, Any]] = context.get("pid_map") or {}
        parent_info = pid_map.get(ppid, {})
        src: Dict[str, Any] = {"type": "process", "pid": ppid}
        if parent_info.get("image"):
            src["image"] = parent_info["image"]
        if parent_info.get("user"):
            src["user"] = parent_info["user"]
        if computer:
            src["computer"] = computer
    else:
        src = dict(_SYSTEM_ENTITY)

    fields: Dict[str, Any] = {}
    if cmdline:
        fields["command_line"] = cmdline
    if ts:
        fields["create_time"] = ts.isoformat()

    return Event(
        action_type="process_create",
        ts=ts,
        src_entity=src,
        dst_entity=dst,
        fields=fields,
        source={
            "provider": "velociraptor",
            "artifact": _ARTIFACT,
            "computer": computer,
        },
    )


def _normalize(row: Dict[str, Any]) -> Dict[str, Any]:
    return {k.lower(): v for k, v in row.items()}


def _intish(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_ts(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
