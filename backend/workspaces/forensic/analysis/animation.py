"""
Forensic animation response builder.

Converts the forensic graph cache into an animation event list compatible
with the core NodeAnimationResponse format:
  events: [{type, session_id, src, dst, time, protocol, color, bytes, packets}]
  nodes:  {node_id: {is_spotlight, label, color}}

Each forensic event becomes a single 'start' event (no paired 'end' — the
frontend recency window trims the active set so older events fade without
requiring explicit end events in the stream).

Events are sorted by time ascending. Events with no parseable timestamp are
assigned a synthetic time so they still appear in the animation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set


def _ts_epoch(ts: Any) -> Optional[float]:
    """Convert a ts value (ISO string, datetime, or None) to float epoch."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, datetime):
        return ts.timestamp()
    if isinstance(ts, str):
        try:
            # Python 3.7+: fromisoformat handles most ISO 8601 variants
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.timestamp()
        except (ValueError, AttributeError):
            return None
    return None


def build_forensic_animation_response(
    graph_cache: Dict[str, Any],
    node_ids: Set[str],
) -> Dict[str, Any]:
    """
    Build animation events + node metadata from the forensic graph cache.

    graph_cache: ForensicStore.graph_cache — {'nodes': [...], 'edges': [...]}
    node_ids:    spotlight node IDs (empty set = include all edges)

    Returns a dict matching NodeAnimationResponse shape:
      {'events': [...], 'nodes': {...}}
    """
    nodes_list: List[Dict[str, Any]] = graph_cache.get("nodes", [])
    edges_list: List[Dict[str, Any]] = graph_cache.get("edges", [])

    # Build a node lookup for metadata
    node_map: Dict[str, Dict[str, Any]] = {n["id"]: n for n in nodes_list if "id" in n}

    events: List[Dict[str, Any]] = []
    involved_nodes: Set[str] = set()
    counter = 0

    for edge in edges_list:
        src = edge.get("source") or edge.get("src")
        dst = edge.get("target") or edge.get("dst")
        if not src or not dst:
            continue

        # Filter: if node_ids given, only include edges involving a spotlight node
        if node_ids and src not in node_ids and dst not in node_ids:
            continue

        edge_color = edge.get("color") or "#8b949e"
        action_type = edge.get("type", "unknown")

        for ev in edge.get("events", []):
            epoch = _ts_epoch(ev.get("ts"))
            ev_action = ev.get("action_type") or action_type

            events.append({
                "type":       "start",
                "session_id": f"fev_{counter}",
                "src":        src,
                "dst":        dst,
                "time":       epoch if epoch is not None else 0.0,
                "protocol":   ev_action,
                "color":      edge_color,
                "bytes":      0,
                "packets":    1,
                "action_type": ev_action,
            })
            involved_nodes.add(src)
            involved_nodes.add(dst)
            counter += 1

    # Sort by time; stable sort preserves edge order for ties
    events.sort(key=lambda e: e["time"])

    # Assign synthetic increasing times for events with time=0 that collide,
    # so the animation slider has distinct frames. Add 1ms gap per event.
    for i, ev in enumerate(events):
        if ev["time"] == 0.0:
            ev["time"] = float(i) * 0.001

    # Build node metadata
    node_meta: Dict[str, Dict[str, Any]] = {}
    for nid in involved_nodes:
        n = node_map.get(nid, {})
        node_meta[nid] = {
            "is_spotlight": nid in node_ids,
            "label":        n.get("label") or nid,
            "color":        n.get("color") or "#4fc3f7",
            "type":         n.get("type") or "process",
        }

    return {"events": events, "nodes": node_meta}
