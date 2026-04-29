"""
Velociraptor Windows.Network.Netstat artifact dissector.

One row = one open network connection at collection time. Produces
"network_connect" Events (process → endpoint). LISTEN, TIME_WAIT, and
loopback-only rows are skipped. Uses context["pid_map"] to resolve
pid → image/user so process nodes merge with pslist-sourced nodes.

CSV columns consumed: Pid, FamilyString, TypeString, Status, Laddr.IP,
Laddr.Port, Raddr.IP, Raddr.Port, Timestamp (case-insensitive).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from workspaces.forensic.parser.event import Event

from . import register_artifact_dissector

_ARTIFACT = "Windows.Network.Netstat"

_SKIP_STATUSES = {"listen", "time_wait", "close_wait", "closed", "fin_wait1",
                  "fin_wait2", "syn_sent", "syn_received", "last_ack"}
_LOOPBACK = {"0.0.0.0", "::", "::1", "127.0.0.1"}


@register_artifact_dissector(_ARTIFACT)
def dissect(row: Dict[str, Any], context: Dict[str, Any]) -> Optional[Event]:
    r = _normalize(row)

    status = (r.get("status") or "").lower()
    if status in _SKIP_STATUSES:
        return None

    pid         = _intish(r.get("pid"))
    remote_ip   = str(r.get("raddr.ip") or "").strip()
    remote_port = _intish(r.get("raddr.port"))
    local_ip    = str(r.get("laddr.ip") or "").strip()
    local_port  = _intish(r.get("laddr.port"))
    proto       = (r.get("typestring") or "").lower()
    computer    = context.get("computer") or ""
    ts          = _parse_ts(r.get("timestamp") or "")

    if not remote_ip or remote_ip in _LOOPBACK:
        return None
    if remote_port is None or remote_port == 0:
        return None

    pid_map: Dict[int, Dict[str, Any]] = context.get("pid_map") or {}
    proc_info = pid_map.get(pid, {}) if pid is not None else {}

    src: Dict[str, Any] = {"type": "process"}
    if pid is not None:
        src["pid"] = pid
    if proc_info.get("image"):
        src["image"] = proc_info["image"]
    if proc_info.get("user"):
        src["user"] = proc_info["user"]
    if computer:
        src["computer"] = computer
    if len(src) <= 1:
        return None  # can't identify the process

    dst: Dict[str, Any] = {"type": "endpoint", "ip": remote_ip, "port": remote_port}

    fields: Dict[str, Any] = {}
    if proto:
        fields["protocol"] = proto
    if local_ip:
        fields["local_ip"] = local_ip
    if local_port is not None:
        fields["local_port"] = local_port
    if status:
        fields["status"] = status

    return Event(
        action_type="network_connect",
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
