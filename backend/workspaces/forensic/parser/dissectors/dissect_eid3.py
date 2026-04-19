"""
Sysmon EID 3 — NetworkConnect.

One "process opened a network connection" event. Produces an Event with:
  - action_type   : "network_connect"
  - src_entity    : the initiating process (ProcessGuid/ProcessId/Image/User)
  - dst_entity    : the *remote* endpoint (direction-aware, see below)
  - fields        : protocol, initiated flag, local_ip/local_port, both hostnames
  - ts            : UtcTime from EventData (preferred) or SystemTime from header

Direction handling
------------------
Sysmon records both endpoints regardless of which side initiated the flow.
The `Initiated` field tells us whether *this* host opened the connection:

  - Initiated=True  → we called out. Local = Source, Remote = Destination.
  - Initiated=False → they called in. Local = Destination, Remote = Source.

The Event model wants a single "whom did the actor talk to", so `dst_entity`
is always the remote endpoint. `fields` preserves the local side and the
raw Initiated flag so nothing is lost and direction stays recoverable.

Sysmon EID 3 EventData fields referenced:
  UtcTime, ProcessGuid, ProcessId, Image, User, Protocol, Initiated,
  SourceIsIpv6, SourceIp, SourceHostname, SourcePort, SourcePortName,
  DestinationIsIpv6, DestinationIp, DestinationHostname, DestinationPort,
  DestinationPortName, RuleName.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from workspaces.forensic.parser.event import Event

from . import register_dissector


@register_dissector(3)
def dissect(raw: Dict[str, Any]) -> Optional[Event]:
    data: Dict[str, str] = raw.get("event_data") or {}

    src = _process_entity(
        guid=data.get("ProcessGuid"),
        pid=data.get("ProcessId"),
        image=data.get("Image"),
        user=data.get("User"),
    )

    initiated = _parse_bool(data.get("Initiated"))

    # "Remote" side is the opposite of whoever this host is acting as.
    # initiated=True  → we called out, remote = Destination
    # initiated=False → they called in, remote = Source
    # initiated=None (unparseable) → default to Destination, matches Sysmon's
    # own directional convention (Source is usually the initiator).
    remote_on_dst = initiated is not False  # True or None → Destination
    if remote_on_dst:
        remote_ip       = data.get("DestinationIp")
        remote_port     = data.get("DestinationPort")
        remote_host     = data.get("DestinationHostname")
        remote_portname = data.get("DestinationPortName")
        remote_ipv6     = _parse_bool(data.get("DestinationIsIpv6"))
        local_ip        = data.get("SourceIp")
        local_port      = data.get("SourcePort")
        local_host      = data.get("SourceHostname")
        local_portname  = data.get("SourcePortName")
    else:
        remote_ip       = data.get("SourceIp")
        remote_port     = data.get("SourcePort")
        remote_host     = data.get("SourceHostname")
        remote_portname = data.get("SourcePortName")
        remote_ipv6     = _parse_bool(data.get("SourceIsIpv6"))
        local_ip        = data.get("DestinationIp")
        local_port      = data.get("DestinationPort")
        local_host      = data.get("DestinationHostname")
        local_portname  = data.get("DestinationPortName")

    dst = _endpoint_entity(
        ip=remote_ip,
        port=remote_port,
        hostname=remote_host,
        port_name=remote_portname,
        ipv6=remote_ipv6,
    )

    fields: Dict[str, Any] = {
        "protocol":       (data.get("Protocol") or "").lower(),
        "initiated":      initiated,
        "local_ip":       local_ip or "",
        "local_port":     _intish(local_port),
        "local_hostname": local_host or "",
        "local_port_name": local_portname or "",
        "rule_name":      data.get("RuleName") or "",
    }
    # Drop empty / None to match EID 1 style.
    fields = {k: v for k, v in fields.items() if v not in ("", None)}

    ts = _pick_ts(data, raw)

    return Event(
        action_type="network_connect",
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


def _endpoint_entity(
    *,
    ip: Optional[str],
    port: Optional[str],
    hostname: Optional[str],
    port_name: Optional[str],
    ipv6: Optional[bool],
) -> Dict[str, Any]:
    out: Dict[str, Any] = {"type": "endpoint"}
    if ip:
        out["ip"] = ip
    if port:
        p = _intish(port)
        if p is not None:
            out["port"] = p
    if hostname:
        out["hostname"] = hostname
    if port_name:
        out["port_name"] = port_name
    if ipv6 is not None:
        out["ipv6"] = ipv6
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


def _parse_bool(value: Optional[str]) -> Optional[bool]:
    """Sysmon writes booleans as the strings 'True' / 'False'."""
    if value is None:
        return None
    v = value.strip().lower()
    if v == "true":
        return True
    if v == "false":
        return False
    return None


def _intish(value: Optional[str]) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
