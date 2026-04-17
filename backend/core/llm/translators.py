"""
LLM field translators.
Renames terse internal fields to LLM-legible names, caps large arrays,
and makes direction semantics explicit. Deterministic — never adds interpretation.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional

# Max items in any array sent to the LLM
_MAX_ARRAY = 10
_MAX_SESSIONS = 5
_MAX_ALERTS = 8
_MAX_EVIDENCE_ITEMS = 12


# ── Node translation ──────────────────────────────────────────────────────────

def translate_node(node: Dict[str, Any]) -> Dict[str, Any]:
    """Return a LLM-legible version of a graph node dict."""
    if not node:
        return {}
    out: Dict[str, Any] = {}

    out["node_id"] = node.get("id", "")
    out["ip_addresses"] = node.get("ips", [])
    out["mac_addresses"] = node.get("macs", [])
    out["mac_vendors"] = node.get("mac_vendors", [])
    out["protocols_seen"] = node.get("protocols", [])
    out["total_bytes"] = node.get("total_bytes", 0)
    out["packet_count"] = node.get("packet_count", 0)
    out["is_private_address"] = node.get("is_private", False)
    out["hostnames"] = node.get("hostnames", [])[:_MAX_ARRAY]
    out["outbound_ttls"] = node.get("ttls_out", [])[:5]
    out["inbound_ttls"] = node.get("ttls_in", [])[:5]
    out["top_destination_ports"] = node.get("top_dst_ports", [])[:_MAX_ARRAY]
    out["top_source_ports"] = node.get("top_src_ports", [])[:_MAX_ARRAY]
    out["top_neighbors_by_bytes"] = node.get("top_neighbors", [])[:_MAX_ARRAY]
    out["top_protocols_by_bytes"] = node.get("top_protocols", [])[:_MAX_ARRAY]

    if node.get("os_guess"):
        out["os_guess"] = node["os_guess"]

    role_data = node.get("plugin_data", {}).get("network_role", {})
    if isinstance(role_data, dict) and role_data.get("role"):
        out["network_role"] = role_data.get("role")
        evidence = role_data.get("evidence", [])
        if evidence:
            out["network_role_evidence"] = evidence[:3]

    if node.get("metadata"):
        out["researcher_metadata"] = node["metadata"]

    return out


# ── Edge translation ──────────────────────────────────────────────────────────

def translate_edge(edge: Dict[str, Any]) -> Dict[str, Any]:
    """Return a LLM-legible version of a graph edge dict."""
    if not edge:
        return {}
    out: Dict[str, Any] = {}

    out["edge_id"] = edge.get("id", "")
    out["initiator"] = edge.get("source", "")          # renamed: source → initiator
    out["responder"] = edge.get("target", "")          # renamed: target → responder
    out["protocol"] = edge.get("protocol", "")
    out["total_bytes"] = edge.get("total_bytes", 0)
    out["packet_count"] = edge.get("packet_count", 0)
    out["first_seen"] = edge.get("first_seen")
    out["last_seen"] = edge.get("last_seen")
    out["ports"] = edge.get("ports", [])[:_MAX_ARRAY]
    out["has_tls"] = edge.get("has_tls", False)
    out["has_http"] = edge.get("has_http", False)
    out["has_dns"] = edge.get("has_dns", False)

    # Detail fields (present on edge detail response, not graph summary)
    if edge.get("tls_snis"):
        out["tls_server_names"] = edge["tls_snis"][:_MAX_ARRAY]       # renamed
    if edge.get("tls_versions"):
        out["tls_versions"] = edge["tls_versions"][:_MAX_ARRAY]
    if edge.get("tls_ja3"):
        out["tls_ja3_hashes"] = edge["tls_ja3"][:_MAX_ARRAY]
    if edge.get("tls_ja4"):
        out["tls_ja4_hashes"] = edge["tls_ja4"][:_MAX_ARRAY]
    if edge.get("http_fwd_hosts"):
        out["forward_http_hosts"] = edge["http_fwd_hosts"][:_MAX_ARRAY]    # renamed
    if edge.get("http_fwd_user_agents"):
        out["forward_http_user_agents"] = edge["http_fwd_user_agents"][:_MAX_ARRAY]   # renamed
    if edge.get("http_fwd_methods"):
        out["forward_http_methods"] = edge["http_fwd_methods"][:_MAX_ARRAY]
    if edge.get("http_rev_status_codes"):
        out["reverse_http_status_codes"] = edge["http_rev_status_codes"][:_MAX_ARRAY]
    if edge.get("dns_queries"):
        out["dns_queries"] = edge["dns_queries"][:_MAX_ARRAY]
    if edge.get("dns_responses"):
        out["dns_responses"] = edge["dns_responses"][:_MAX_ARRAY]

    if edge.get("has_protocol_conflict"):
        out["protocol_conflict_detected"] = True
        out["protocol_by_port"] = edge.get("protocol_by_port", [])
        out["protocol_by_payload"] = edge.get("protocol_by_payload", [])

    return out


# ── Session translation ───────────────────────────────────────────────────────

def translate_session(session: Dict[str, Any]) -> Dict[str, Any]:
    """Return a LLM-legible version of a session dict."""
    if not session:
        return {}
    out: Dict[str, Any] = {}

    out["session_id"] = session.get("id", "")
    out["initiator"] = session.get("src_ip", "")       # renamed
    out["responder"] = session.get("dst_ip", "")       # renamed
    out["initiator_port"] = session.get("src_port")
    out["responder_port"] = session.get("dst_port")
    out["protocol"] = session.get("protocol", "")
    out["transport"] = session.get("transport", "")
    out["total_bytes"] = session.get("total_bytes", 0)
    out["packet_count"] = session.get("packet_count", 0)
    out["duration_seconds"] = session.get("duration")
    out["start_time"] = session.get("start_time")
    out["has_tcp_handshake"] = session.get("has_handshake", False)
    out["has_tcp_reset"] = session.get("has_reset", False)
    out["has_tcp_fin"] = session.get("has_fin", False)

    # Protocol-specific fields
    if session.get("tls_sni"):
        out["tls_server_name"] = session["tls_sni"]
    if session.get("tls_version"):
        out["tls_version"] = session["tls_version"]
    if session.get("http_host"):
        out["http_host"] = session["http_host"]
    if session.get("http_user_agent"):
        out["http_user_agent"] = session["http_user_agent"]
    if session.get("dns_query"):
        out["dns_query"] = session["dns_query"]
    if session.get("dns_response"):
        out["dns_response"] = session["dns_response"]

    # Credential presence (boolean hints only — no actual credentials sent)
    cred_hints = []
    if session.get("ftp_has_credentials"):
        cred_hints.append("FTP credentials observed")
    if session.get("http_fwd_has_auth"):
        cred_hints.append("HTTP authentication header observed")
    if session.get("smtp_has_auth"):
        cred_hints.append("SMTP AUTH observed")
    if cred_hints:
        out["credential_indicators"] = cred_hints

    return out


# ── Alert translation ─────────────────────────────────────────────────────────

def translate_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Return a LLM-legible version of an alert/AlertRecord dict."""
    if not alert:
        return {}
    out: Dict[str, Any] = {}

    out["alert_id"] = alert.get("id", "")
    out["alert_title"] = alert.get("title", "")
    out["alert_summary"] = alert.get("subtitle", "")
    out["severity"] = alert.get("severity", "")
    out["detector"] = alert.get("detector", "") or alert.get("source_name", "")
    out["timestamp"] = alert.get("timestamp")
    out["primary_ip"] = alert.get("src_ip")
    out["secondary_ip"] = alert.get("dst_ip")
    out["involved_nodes"] = alert.get("node_ids", [])
    out["involved_edges"] = alert.get("edge_ids", [])
    out["involved_sessions"] = alert.get("session_ids", [])

    evidence = alert.get("evidence", [])[:_MAX_EVIDENCE_ITEMS]
    if evidence:
        out["evidence"] = evidence

    return out


# ── Stats / overview translation ──────────────────────────────────────────────

def translate_stats_overview(stats: Dict[str, Any]) -> Dict[str, Any]:
    """Return a compact, LLM-legible summary of capture stats."""
    if not stats:
        return {}
    out: Dict[str, Any] = {}

    out["total_packets"] = stats.get("total_packets", 0)
    out["total_bytes"] = stats.get("total_bytes", 0)
    out["unique_ip_addresses"] = stats.get("unique_ips", 0)
    out["total_sessions"] = stats.get("total_sessions", 0)
    out["duration_seconds"] = stats.get("duration", 0)
    out["packets_per_second"] = stats.get("packets_per_second", 0)

    protocols = stats.get("protocols", {})
    # Top 8 protocols by bytes
    top_protos = sorted(protocols.items(), key=lambda x: x[1].get("bytes", 0), reverse=True)[:8]
    out["top_protocols"] = [
        {"protocol": k, "packets": v.get("packets", 0), "bytes": v.get("bytes", 0)}
        for k, v in top_protos
    ]

    top_talkers = stats.get("top_talkers", [])[:8]
    out["top_talkers_by_bytes"] = top_talkers

    return out


def cap_list(lst: Optional[List], limit: int = _MAX_ARRAY) -> List:
    """Cap any list to the given limit."""
    if not lst:
        return []
    return lst[:limit]
