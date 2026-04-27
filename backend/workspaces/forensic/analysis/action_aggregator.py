"""
Forensic action aggregator — Phase 5.

`build_forensic_graph(events)` collapses a flat list of `Event` records into
a graph dict `{"nodes": [...], "edges": [...]}` using the single-pair model:
one node per entity, one edge per (src_entity_id, dst_entity_id) pair — all
event types accumulate as an `events` list on that edge.

Entity ID scheme (locked 2026-04-26):
  process  → "fx:proc:{ProcessGuid}"  | fallback: "fx:proc:{computer}:{image}:{pid}"
  file     → "fx:file:{path.lower()}"
  registry → "fx:reg:{key.lower()}"
  endpoint → "fx:net:{ip}:{port}"     | fallback: "fx:net:{hostname}:{port}"

Action-type → edge-type mapping:
  "process_create"  → "spawned"
  "network_connect" → "connected"
  "file_create"     → "wrote"
  "registry_set"    → "set_value"
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from workspaces.forensic.parser.event import Event
from workspaces.forensic.schema import FORENSIC_SCHEMA

# Schema is the single source of truth for node/edge colours. The aggregator
# stamps them onto each node/edge dict so the frontend renderer (which reads
# `node.color` / `edge.color` via the schema-agnostic colour primitives) gets
# the right colour without redeclaring it.
_NODE_COLORS: Dict[str, str] = {nt.name: nt.color for nt in FORENSIC_SCHEMA.node_types}
_EDGE_COLORS: Dict[str, str] = {et.name: et.color for et in FORENSIC_SCHEMA.edge_types}


# ---------------------------------------------------------------------------
# Entity ID helpers
# ---------------------------------------------------------------------------

def _process_id(entity: Dict[str, Any], computer: str = "") -> Optional[str]:
    guid = entity.get("guid")
    if guid:
        return f"fx:proc:{guid}"
    image = entity.get("image") or ""
    pid = entity.get("pid") or ""
    if image or pid:
        host = computer or "unknown"
        return f"fx:proc:{host}:{image}:{pid}"
    return None


def _file_id(entity: Dict[str, Any]) -> Optional[str]:
    path = entity.get("path")
    if path:
        return f"fx:file:{path.lower()}"
    return None


def _registry_id(entity: Dict[str, Any]) -> Optional[str]:
    key = entity.get("key")
    if key:
        return f"fx:reg:{key.lower()}"
    return None


def _endpoint_id(entity: Dict[str, Any]) -> Optional[str]:
    ip = entity.get("ip")
    port = entity.get("port")
    hostname = entity.get("hostname")
    if ip and port is not None:
        return f"fx:net:{ip}:{port}"
    if hostname and port is not None:
        return f"fx:net:{hostname}:{port}"
    if ip:
        return f"fx:net:{ip}"
    if hostname:
        return f"fx:net:{hostname}"
    return None


def _entity_id(entity: Dict[str, Any], computer: str = "") -> Optional[str]:
    t = entity.get("type")
    if t == "process":
        return _process_id(entity, computer)
    if t == "file":
        return _file_id(entity)
    if t == "registry":
        return _registry_id(entity)
    if t == "endpoint":
        return _endpoint_id(entity)
    return None


# ---------------------------------------------------------------------------
# Node builder
# ---------------------------------------------------------------------------

def _make_node(entity_id: str, entity: Dict[str, Any], computer: str = "") -> Dict[str, Any]:
    t = entity.get("type", "process")
    node: Dict[str, Any] = {
        "id": entity_id,
        "type": t,
        "color": _NODE_COLORS.get(t, "#4fc3f7"),
        # Phase 5.7 graphDisplay weight fields. event_count = times this entity
        # appeared as src or dst (kept alongside packet_count for back-compat
        # with the renderer's network-shaped fallback). connection_count and
        # child_count are populated in a finalisation pass below — tracked here
        # so graphDisplay defaults render a non-null radius even before that
        # pass (e.g. for node types that never see those edge classes).
        "event_count":      0,
        "connection_count": 0,
        "child_count":      0,
    }
    if t == "process":
        node["image"]   = entity.get("image") or ""
        node["guid"]    = entity.get("guid") or ""
        node["pid"]     = entity.get("pid")
        node["user"]    = entity.get("user") or ""
        if computer:
            node["computer"] = computer
        node["label"]   = os.path.basename(node["image"]) if node["image"] else entity_id
    elif t == "file":
        path = entity.get("path") or ""
        node["path"]      = path
        node["extension"] = os.path.splitext(path)[1].lstrip(".").lower() if path else ""
        node["label"]     = os.path.basename(path) if path else entity_id
    elif t == "registry":
        key = entity.get("key") or ""
        node["key"]   = key
        node["hive"]  = key.split("\\")[0] if key else ""
        node["label"] = key.split("\\")[-1] if key else entity_id
    elif t == "endpoint":
        node["ip"]       = entity.get("ip") or ""
        node["port"]     = entity.get("port")
        node["hostname"] = entity.get("hostname") or ""
        node["label"]    = entity.get("hostname") or entity.get("ip") or entity_id
    return node


def _merge_node_fields(existing: Dict[str, Any], entity: Dict[str, Any], computer: str = "") -> None:
    """Back-fill fields that may be missing from earlier events (e.g. User)."""
    t = entity.get("type")
    if t == "process":
        if not existing.get("image") and entity.get("image"):
            existing["image"] = entity["image"]
            existing["label"] = os.path.basename(entity["image"])
        if not existing.get("user") and entity.get("user"):
            existing["user"] = entity["user"]
        if not existing.get("guid") and entity.get("guid"):
            existing["guid"] = entity["guid"]
        if not existing.get("computer") and computer:
            existing["computer"] = computer
    elif t == "endpoint":
        if not existing.get("hostname") and entity.get("hostname"):
            existing["hostname"] = entity["hostname"]
            if not existing.get("ip"):
                existing["label"] = entity["hostname"]


# ---------------------------------------------------------------------------
# Action-type → edge-type
# ---------------------------------------------------------------------------

_ACTION_TO_EDGE_TYPE: Dict[str, str] = {
    "process_create":  "spawned",
    "network_connect": "connected",
    "file_create":     "wrote",
    "registry_set":    "set_value",
}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def build_forensic_graph(events: List[Event]) -> Dict[str, Any]:
    """
    Collapse events into `{"nodes": [...], "edges": [...]}`.

    Single pass:
      1. For each event, resolve src and dst entity IDs.
      2. Upsert src / dst into the node registry.
      3. Upsert an edge for the (src_id, dst_id) pair; append event to its list.
    """
    node_registry: Dict[str, Dict[str, Any]] = {}
    edge_registry: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for ev in events:
        computer = ev.source.get("computer") or ""

        src_id = _entity_id(ev.src_entity, computer) if ev.src_entity else None
        dst_id = _entity_id(ev.dst_entity, computer) if ev.dst_entity else None

        if not src_id or not dst_id:
            continue

        # Upsert nodes. packet_count tracks event participation so the renderer's
        # network-shaped fallback (Math.sqrt(packet_count)) still produces a
        # valid radius. event_count is the schema-declared field used by the
        # forensic graphDisplay weight modes.
        if src_id not in node_registry:
            node_registry[src_id] = _make_node(src_id, ev.src_entity, computer)
        else:
            _merge_node_fields(node_registry[src_id], ev.src_entity, computer)
        node_registry[src_id]["packet_count"] = node_registry[src_id].get("packet_count", 0) + 1
        node_registry[src_id]["event_count"]  = node_registry[src_id].get("event_count", 0) + 1

        if dst_id not in node_registry:
            node_registry[dst_id] = _make_node(dst_id, ev.dst_entity, computer)
        else:
            _merge_node_fields(node_registry[dst_id], ev.dst_entity, computer)
        node_registry[dst_id]["packet_count"] = node_registry[dst_id].get("packet_count", 0) + 1
        node_registry[dst_id]["event_count"]  = node_registry[dst_id].get("event_count", 0) + 1

        # Upsert edge
        edge_key = (src_id, dst_id)
        if edge_key not in edge_registry:
            edge_type = _ACTION_TO_EDGE_TYPE.get(ev.action_type, "unknown")
            edge_registry[edge_key] = {
                "id":          f"{src_id}|{dst_id}",
                "source":      src_id,
                "target":      dst_id,
                "type":        edge_type,
                "color":       _EDGE_COLORS.get(edge_type, "#8b949e"),
                "events":      [],
                "count":       0,
                "event_count": 0,
                "ts_first":    None,
                "ts_last":     None,
            }
        edge = edge_registry[edge_key]

        ts_iso: Optional[str] = ev.ts.isoformat() if isinstance(ev.ts, datetime) else None
        edge["events"].append({
            "action_type": ev.action_type,
            "ts":          ts_iso,
            "fields":      ev.fields,
            "source":      ev.source,
        })
        edge["count"]       += 1
        edge["event_count"]  = edge["count"]

        if ts_iso:
            if edge["ts_first"] is None or ts_iso < edge["ts_first"]:
                edge["ts_first"] = ts_iso
            if edge["ts_last"] is None or ts_iso > edge["ts_last"]:
                edge["ts_last"] = ts_iso

        # Update edge type: the first event's action wins; if events of multiple
        # types accumulate, mark as "mixed" (rare in practice with current EIDs).
        if edge["type"] != _ACTION_TO_EDGE_TYPE.get(ev.action_type, "unknown"):
            edge["type"] = "mixed"
            edge["color"] = "#8b949e"

    # Finalisation pass: per-source per-edge-type counters used by the forensic
    # graphDisplay weight modes (`connection_count`, `child_count`). Run after
    # all events are aggregated so we count finalised edges, not partial state.
    for (src, _dst), edge in edge_registry.items():
        node = node_registry.get(src)
        if node is None:
            continue
        if edge["type"] == "connected":
            node["connection_count"] = node.get("connection_count", 0) + 1
        elif edge["type"] == "spawned":
            node["child_count"] = node.get("child_count", 0) + 1

    return {
        "nodes": list(node_registry.values()),
        "edges": list(edge_registry.values()),
    }
