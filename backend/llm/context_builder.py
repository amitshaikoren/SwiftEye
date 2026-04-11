"""
Context builder — assembles a question-specific context packet from store data.

The context packet has these sections:
  scope              — normalised scope mode + active filters
  capture_meta       — file/source, counts, time span
  overview           — compact scoped summary
  selection_context  — selected entity (highest-priority evidence)
  retrieved_context  — additional entities pulled by the question
  retrieval_manifest — which evidence surfaces are still available
  limitations        — scope gaps + uncertainty reminders

All retrieval is deterministic. No inference, no model calls.
"""

from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional, Set

import store as _store

from .contracts import ChatRequest, ScopeSpec, SelectionState, ViewerState
from .question_tags import (
    TAG_BROAD_OVERVIEW, TAG_ENTITY_NODE, TAG_ENTITY_EDGE, TAG_ENTITY_SESSION,
    TAG_ALERT_EVIDENCE, TAG_DNS, TAG_TLS, TAG_HTTP, TAG_CREDENTIALS,
    TAG_ATTRIBUTION_RISK, TAG_BACKGROUND, TAG_MIXED, TAG_UNRELATED,
)
from .translators import (
    translate_node, translate_edge, translate_session, translate_alert,
    translate_stats_overview, cap_list,
)

logger = logging.getLogger("swifteye.llm.context_builder")

_MAX_RELATED_EDGES    = 5
_MAX_RELATED_SESSIONS = 5
_MAX_RELATED_ALERTS   = 6
_MAX_BROAD_SESSIONS   = 3


def build_context_packet(
    request: ChatRequest,
    tags: List[str],
) -> Dict[str, Any]:
    """
    Build and return a context packet dict for the given request + resolved tags.
    Reads exclusively from the global store singleton.
    """
    st = _store.store
    scope = request.scope
    sel   = request.selection
    vs    = request.viewer_state

    packet: Dict[str, Any] = {}

    # ── scope ─────────────────────────────────────────────────────────────────
    packet["scope"] = _build_scope_section(scope, vs, tags)

    # ── capture_meta ──────────────────────────────────────────────────────────
    packet["capture_meta"] = _build_capture_meta(st)

    # ── overview ──────────────────────────────────────────────────────────────
    packet["overview"] = _build_overview(st, scope, vs)

    # ── selection_context ─────────────────────────────────────────────────────
    sel_ctx = _build_selection_context(st, scope, sel, tags)
    if sel_ctx:
        packet["selection_context"] = sel_ctx

    # ── retrieved_context ─────────────────────────────────────────────────────
    retrieved, surfaces = _build_retrieved_context(st, scope, sel, vs, tags, request.options)
    if retrieved:
        packet["retrieved_context"] = retrieved

    # ── retrieval_manifest ────────────────────────────────────────────────────
    packet["retrieval_manifest"] = _build_manifest(st, surfaces)

    # ── limitations ───────────────────────────────────────────────────────────
    packet["limitations"] = _build_limitations(st, scope, tags)

    return packet


# ── Section builders ──────────────────────────────────────────────────────────

def _build_scope_section(scope: ScopeSpec, vs: ViewerState, tags: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"mode": scope.mode}

    if vs.time_start is not None and vs.time_end is not None:
        out["time_range"] = {"start": vs.time_start, "end": vs.time_end}
    if vs.protocols:
        out["active_protocols"] = vs.protocols
    if vs.search:
        out["search_filter"] = vs.search
    if vs.subnet_grouping:
        out["subnet_grouping"] = True
        out["subnet_prefix"] = vs.subnet_prefix
    if vs.merge_by_mac:
        out["merge_by_mac"] = True
    if not vs.include_ipv6:
        out["ipv6_hidden"] = True

    out["question_tags"] = tags
    return out


def _build_capture_meta(st) -> Dict[str, Any]:
    if not st.is_loaded:
        return {"loaded": False}

    stats = st.stats or {}
    out: Dict[str, Any] = {
        "capture_id": st.capture_id or "",
        "file_name": st.file_name or "",
        "source_files": st.source_files or [],
        "packet_count": len(st.packets),
        "session_count": len(st.sessions),
    }
    if stats.get("first_timestamp") and stats.get("last_timestamp"):
        out["time_span_seconds"] = round(
            stats["last_timestamp"] - stats["first_timestamp"], 3
        )
        out["first_timestamp"] = stats["first_timestamp"]
        out["last_timestamp"] = stats["last_timestamp"]
    return out


def _build_overview(st, scope: ScopeSpec, vs: ViewerState) -> Dict[str, Any]:
    if not st.is_loaded:
        return {"note": "No capture loaded."}

    stats = st.stats or {}
    out: Dict[str, Any] = {}

    out["stats_summary"] = translate_stats_overview(stats)

    # Alert summary
    alerts = st.alerts or []
    if alerts:
        sev_counts: Dict[str, int] = {}
        for a in alerts:
            sev = a.get("severity", "info") if isinstance(a, dict) else getattr(a, "severity", "info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        out["alert_summary"] = {
            "total": len(alerts),
            "by_severity": sev_counts,
        }
    else:
        out["alert_summary"] = {"total": 0}

    # Analysis plugin summary (traffic characterisation etc.)
    from services.capture import get_analysis_results
    analysis = get_analysis_results() or {}
    if analysis:
        # Pass concise summaries only — not raw data dumps
        concise: Dict[str, Any] = {}
        for name, result in analysis.items():
            if isinstance(result, dict) and "summary" in result:
                concise[name] = result["summary"]
            elif isinstance(result, dict):
                # Top-level non-list values only (skip large arrays)
                concise[name] = {k: v for k, v in result.items()
                                 if not isinstance(v, (list, dict)) or k.endswith("_summary")}
        if concise:
            out["analysis_summary"] = concise

    return out


def _build_selection_context(
    st, scope: ScopeSpec, sel: SelectionState, tags: List[str]
) -> Optional[Dict[str, Any]]:
    """Build the highest-priority evidence section from explicit selection."""

    # Alert selected
    if sel.alert_id or scope.entity_type == "alert":
        aid = sel.alert_id or scope.entity_id
        alert = _find_alert(st, aid)
        if alert:
            return {"type": "alert", "alert": translate_alert(_alert_to_dict(alert))}

    # Edge selected
    if sel.edge_id or scope.entity_type == "edge":
        eid = sel.edge_id or scope.entity_id
        edge = _find_edge(st, eid)
        if edge:
            return {"type": "edge", "edge": translate_edge(edge)}

    # Session selected
    if sel.session_id or scope.entity_type == "session":
        sid = sel.session_id or scope.entity_id
        session = _find_session(st, sid)
        if session:
            return {"type": "session", "session": translate_session(session)}

    # Node(s) selected
    if sel.node_ids or scope.entity_type == "node":
        node_ids = sel.node_ids or ([scope.entity_id] if scope.entity_id else [])
        nodes = [_find_node(st, nid) for nid in node_ids if _find_node(st, nid)]
        if nodes:
            return {
                "type": "nodes",
                "nodes": [translate_node(n) for n in nodes[:5]],
            }

    return None


def _build_retrieved_context(
    st,
    scope: ScopeSpec,
    sel: SelectionState,
    vs: ViewerState,
    tags: List[str],
    options,
) -> tuple[Dict[str, Any], List[str]]:
    """
    Build additional retrieved evidence based on question tags.
    Returns (retrieved_dict, list_of_surface_names_already_used).
    """
    retrieved: Dict[str, Any] = {}
    surfaces: List[str] = []

    if TAG_UNRELATED in tags:
        return retrieved, surfaces

    # ── Broad overview ────────────────────────────────────────────────────────
    if TAG_BROAD_OVERVIEW in tags and not _has_entity_tag(tags):
        # Protocol highlights
        stats = st.stats or {}
        protos = stats.get("protocols", {})
        top_protos = sorted(protos.items(), key=lambda x: x[1].get("bytes", 0), reverse=True)[:5]
        if top_protos:
            retrieved["protocol_highlights"] = [
                {"protocol": k, "packets": v.get("packets", 0), "bytes": v.get("bytes", 0)}
                for k, v in top_protos
            ]
            surfaces.append("protocol_highlights")

        # Sample sessions
        sessions = cap_list(st.sessions, _MAX_BROAD_SESSIONS)
        if sessions:
            retrieved["sample_sessions"] = [translate_session(s) for s in sessions]
            surfaces.append("sample_sessions")

    # ── Entity: node ──────────────────────────────────────────────────────────
    if TAG_ENTITY_NODE in tags:
        node_ids = sel.node_ids or []
        if not node_ids and scope.entity_id and scope.entity_type == "node":
            node_ids = [scope.entity_id]

        for nid in node_ids[:2]:
            # Related edges
            related_edges = _edges_for_node(st, nid, _MAX_RELATED_EDGES)
            if related_edges:
                retrieved[f"edges_for_{nid}"] = [translate_edge(e) for e in related_edges]
                surfaces.append("related_edges")

            # Related sessions (capped)
            related_sessions = _sessions_for_node(st, nid, _MAX_RELATED_SESSIONS)
            if related_sessions:
                retrieved[f"sessions_for_{nid}"] = [translate_session(s) for s in related_sessions]
                surfaces.append("related_sessions")

        # Related alerts
        rel_alerts = _alerts_for_nodes(st, node_ids, _MAX_RELATED_ALERTS)
        if rel_alerts:
            retrieved["related_alerts"] = [translate_alert(_alert_to_dict(a)) for a in rel_alerts]
            surfaces.append("related_alerts")

    # ── Entity: edge ──────────────────────────────────────────────────────────
    elif TAG_ENTITY_EDGE in tags:
        eid = sel.edge_id or (scope.entity_id if scope.entity_type == "edge" else None)
        if eid:
            sessions = _sessions_for_edge(st, eid, _MAX_RELATED_SESSIONS)
            if sessions:
                retrieved["edge_sessions"] = [translate_session(s) for s in sessions]
                surfaces.append("edge_sessions")
            rel_alerts = _alerts_for_edge(st, eid, _MAX_RELATED_ALERTS)
            if rel_alerts:
                retrieved["related_alerts"] = [translate_alert(_alert_to_dict(a)) for a in rel_alerts]
                surfaces.append("related_alerts")

    # ── Entity: session ───────────────────────────────────────────────────────
    elif TAG_ENTITY_SESSION in tags:
        sid = sel.session_id or (scope.entity_id if scope.entity_type == "session" else None)
        if sid:
            rel_alerts = _alerts_for_session(st, sid, _MAX_RELATED_ALERTS)
            if rel_alerts:
                retrieved["related_alerts"] = [translate_alert(_alert_to_dict(a)) for a in rel_alerts]
                surfaces.append("related_alerts")

    # ── Alert evidence ────────────────────────────────────────────────────────
    if TAG_ALERT_EVIDENCE in tags:
        aid = sel.alert_id or (scope.entity_id if scope.entity_type == "alert" else None)
        if aid:
            alert = _find_alert(st, aid)
            if alert:
                ad = _alert_to_dict(alert)
                # Pull entity context for involved nodes
                for nid in ad.get("node_ids", [])[:2]:
                    node = _find_node(st, nid)
                    if node:
                        retrieved[f"alert_node_{nid}"] = translate_node(node)
                        surfaces.append("alert_entity_context")

    # ── Attribution risk ──────────────────────────────────────────────────────
    if TAG_ATTRIBUTION_RISK in tags:
        # All alerts — most relevant for "who is responsible?" type questions
        alerts = st.alerts or []
        if alerts:
            retrieved["all_alerts"] = [
                translate_alert(_alert_to_dict(a)) for a in alerts[:_MAX_RELATED_ALERTS]
            ]
            surfaces.append("all_alerts_for_attribution")

    return retrieved, surfaces


def _build_manifest(st, used_surfaces: List[str]) -> Dict[str, Any]:
    """List available evidence surfaces that weren't already pulled."""
    available: List[str] = []
    if st.is_loaded:
        if st.sessions:
            available.append("sessions_list")
        if st.alerts:
            available.append("alerts_list")
        if st.graph_cache.get("nodes"):
            available.append("graph_nodes")
        if st.graph_cache.get("edges"):
            available.append("graph_edges")
    used_set = set(used_surfaces)
    return {
        "already_retrieved": used_surfaces,
        "available_for_expansion": [s for s in available if s not in used_set],
    }


def _build_limitations(st, scope: ScopeSpec, tags: List[str]) -> Dict[str, Any]:
    limitations: List[str] = []

    if not st.is_loaded:
        limitations.append("No capture is currently loaded.")
        return {"items": limitations}

    # Source-type gaps
    limitations.append("Raw packet payload bytes are not sent to the model.")
    limitations.append("Packet capture does not include process names or user attribution.")

    # Scope limitations
    if scope.mode == "current_view":
        limitations.append("Analysis is scoped to the currently filtered view, not the full capture.")
    elif scope.mode == "selected_entity":
        limitations.append("Analysis is scoped to the selected entity only.")

    # Attribution uncertainty reminder
    if TAG_ATTRIBUTION_RISK in tags:
        limitations.append(
            "Attacker identity, geographic location, and process attribution cannot be determined "
            "from packet metadata alone without additional corroborating evidence."
        )

    return {"items": limitations}


# ── Store lookup helpers ───────────────────────────────────────────────────────

def _alert_to_dict(alert) -> Dict[str, Any]:
    if isinstance(alert, dict):
        return alert
    if hasattr(alert, "to_dict"):
        return alert.to_dict()
    return vars(alert)


def _find_alert(st, alert_id: Optional[str]):
    if not alert_id:
        return None
    for a in (st.alerts or []):
        aid = a.get("id") if isinstance(a, dict) else getattr(a, "id", None)
        if aid == alert_id:
            return a
    return None


def _find_node(st, node_id: Optional[str]) -> Optional[Dict]:
    if not node_id:
        return None
    for n in (st.graph_cache.get("nodes") or []):
        if n.get("id") == node_id:
            return n
    return None


def _find_edge(st, edge_id: Optional[str]) -> Optional[Dict]:
    if not edge_id:
        return None
    for e in (st.graph_cache.get("edges") or []):
        if e.get("id") == edge_id:
            return e
    return None


def _find_session(st, session_id: Optional[str]) -> Optional[Dict]:
    if not session_id:
        return None
    for s in (st.sessions or []):
        if s.get("id") == session_id:
            return s
    return None


def _edges_for_node(st, node_id: str, limit: int) -> List[Dict]:
    results = []
    for e in (st.graph_cache.get("edges") or []):
        if e.get("source") == node_id or e.get("target") == node_id:
            results.append(e)
            if len(results) >= limit:
                break
    return results


def _sessions_for_node(st, node_id: str, limit: int) -> List[Dict]:
    results = []
    for s in (st.sessions or []):
        if s.get("src_ip") == node_id or s.get("dst_ip") == node_id:
            results.append(s)
            if len(results) >= limit:
                break
    return results


def _sessions_for_edge(st, edge_id: str, limit: int) -> List[Dict]:
    """Match sessions to an edge by src|dst|protocol pattern."""
    if not edge_id or "|" not in edge_id:
        return []
    parts = edge_id.split("|")
    if len(parts) != 3:
        return []
    src, dst, proto = parts
    results = []
    for s in (st.sessions or []):
        s_src = s.get("src_ip", "")
        s_dst = s.get("dst_ip", "")
        s_proto = s.get("protocol", "")
        match = (
            (s_src == src and s_dst == dst) or (s_src == dst and s_dst == src)
        ) and s_proto.upper() == proto.upper()
        if match:
            results.append(s)
            if len(results) >= limit:
                break
    return results


def _alerts_for_nodes(st, node_ids: List[str], limit: int) -> list:
    if not node_ids:
        return []
    node_set = set(node_ids)
    results = []
    for a in (st.alerts or []):
        ad = _alert_to_dict(a)
        if node_set & set(ad.get("node_ids", [])):
            results.append(a)
            if len(results) >= limit:
                break
    return results


def _alerts_for_edge(st, edge_id: str, limit: int) -> list:
    results = []
    for a in (st.alerts or []):
        ad = _alert_to_dict(a)
        if edge_id in ad.get("edge_ids", []):
            results.append(a)
            if len(results) >= limit:
                break
    return results


def _alerts_for_session(st, session_id: str, limit: int) -> list:
    results = []
    for a in (st.alerts or []):
        ad = _alert_to_dict(a)
        if session_id in ad.get("session_ids", []):
            results.append(a)
            if len(results) >= limit:
                break
    return results


def _has_entity_tag(tags: List[str]) -> bool:
    entity_tags = {TAG_ENTITY_NODE, TAG_ENTITY_EDGE, TAG_ENTITY_SESSION, TAG_ALERT_EVIDENCE}
    return bool(entity_tags & set(tags))
