"""
Custom research chart — ad-hoc Plotly figures built from the Research panel UI.

The frontend sends a field-mapping payload; this module extracts the data from
the current capture (packets or sessions) and returns a Plotly figure dict.

== Payload schema ==

  {
    "source":       "packets" | "sessions" | "dns" | "http" | "tls" | "tcp" | "dhcp" | "arp" | "icmp",
    "chart_type":   "scatter" | "bar" | "histogram",
    "x_field":      "<field name>",
    "y_field":      "<field name>",           # omitted for histogram (x is the value)
    "color_field":  "<field name>" | null,
    "size_field":   "<field name>" | null,     # scatter only
    "hover_fields": ["<field>", ...],
    "title":        "<chart title>",
  }

== Field discovery ==

  SOURCE_FIELDS defines the known baseline fields per source.  At schema-request
  time sources_info(packets, sessions) scans a sample of actual packet extra dicts
  and appends any additional scalar keys not already in the static list.  This means
  new dissectors (or new adapter extra keys) automatically appear in the UI without
  any registration — the architecture is self-describing.

  Only scalar values (str / int / float / bool) become fields. Lists, dicts, and
  bytes are skipped. Type is inferred from the first non-None value seen.
"""

import logging
from typing import Any, Dict, List, Optional

import plotly.graph_objects as go

from constants import SWIFTEYE_LAYOUT

logger = logging.getLogger("swifteye.research.custom")

# ── Source definitions ────────────────────────────────────────────────────────

SOURCE_LABELS = {
    "packets":  "All Packets",
    "sessions": "Sessions",
    "dns":      "DNS",
    "http":     "HTTP",
    "tls":      "TLS",
    "tcp":      "TCP",
    "dhcp":     "DHCP",
    "arp":      "ARP",
    "icmp":     "ICMP",
}

# Baseline fields per source — (field_name, human_label, value_type)
# value_type: "numeric" | "text" | "time"
#
# NOTE: base packet fields (orig_len, payload_len, src_ip, dst_ip) are included
# in ALL packet-based sources because _extract_packets always populates them,
# regardless of which protocol filter is active.
SOURCE_FIELDS: Dict[str, List[tuple]] = {
    "packets": [
        ("timestamp",    "Time",           "time"),
        ("src_ip",       "Source IP",      "text"),
        ("dst_ip",       "Dest IP",        "text"),
        ("src_port",     "Source Port",    "numeric"),
        ("dst_port",     "Dest Port",      "numeric"),
        ("protocol",     "Protocol",       "text"),
        ("transport",    "Transport",      "text"),
        ("orig_len",     "Packet Size",    "numeric"),
        ("payload_len",  "Payload Size",   "numeric"),
        ("ttl",          "TTL",            "numeric"),
        ("ip_version",   "IP Version",     "numeric"),
        ("tcp_flags_str","TCP Flags",      "text"),
        ("seq_num",      "Seq Num",        "numeric"),
        ("ack_num",      "Ack Num",        "numeric"),
        ("window_size",  "Window Size",    "numeric"),
    ],
    "sessions": [
        ("start_time",   "Start Time",     "time"),
        ("duration",     "Duration (s)",   "numeric"),
        ("src_ip",       "Source IP",      "text"),
        ("dst_ip",       "Dest IP",        "text"),
        ("src_port",     "Source Port",    "numeric"),
        ("dst_port",     "Dest Port",      "numeric"),
        ("protocol",     "Protocol",       "text"),
        ("transport",    "Transport",      "text"),
        ("total_bytes",  "Total Bytes",    "numeric"),
        ("payload_bytes","Payload Bytes",  "numeric"),
        ("packet_count", "Packet Count",   "numeric"),
    ],
    "dns": [
        ("timestamp",      "Time",          "time"),
        ("src_ip",         "Source IP",     "text"),
        ("dst_ip",         "Dest IP",       "text"),
        ("orig_len",       "Packet Size",   "numeric"),
        ("payload_len",    "Payload Size",  "numeric"),
        ("dns_query",      "Query Name",    "text"),
        ("dns_qtype_name", "Query Type",    "text"),
        ("dns_rcode_name", "Response Code", "text"),
        ("dns_ancount",    "Answer Count",  "numeric"),
        ("dns_qr",         "QR",            "text"),
    ],
    "http": [
        ("timestamp",           "Time",           "time"),
        ("src_ip",              "Source IP",      "text"),
        ("dst_ip",              "Dest IP",        "text"),
        ("orig_len",            "Packet Size",    "numeric"),
        ("payload_len",         "Payload Size",   "numeric"),
        ("http_method",         "Method",         "text"),
        ("http_uri",            "URI",            "text"),
        ("http_host",           "Host",           "text"),
        ("http_status",         "Status Code",    "numeric"),
        ("http_user_agent",     "User-Agent",     "text"),
        ("http_content_length", "Content-Length", "numeric"),
    ],
    "tls": [
        ("timestamp",          "Time",        "time"),
        ("src_ip",             "Source IP",   "text"),
        ("dst_ip",             "Dest IP",     "text"),
        ("orig_len",           "Packet Size", "numeric"),
        ("payload_len",        "Payload Size","numeric"),
        ("tls_sni",            "SNI",         "text"),
        ("tls_record_version", "TLS Version", "text"),
        ("tls_msg_type",       "Msg Type",    "text"),
        ("ja3",                "JA3 Hash",    "text"),
    ],
    "tcp": [
        ("timestamp",    "Time",         "time"),
        ("src_ip",       "Source IP",    "text"),
        ("dst_ip",       "Dest IP",      "text"),
        ("src_port",     "Source Port",  "numeric"),
        ("dst_port",     "Dest Port",    "numeric"),
        ("orig_len",     "Packet Size",  "numeric"),
        ("payload_len",  "Payload Size", "numeric"),
        ("tcp_flags_str","TCP Flags",    "text"),
        ("seq_num",      "Seq Num",      "numeric"),
        ("ack_num",      "Ack Num",      "numeric"),
        ("window_size",  "Window Size",  "numeric"),
    ],
    "dhcp": [
        ("timestamp",         "Time",           "time"),
        ("src_ip",            "Source IP",      "text"),
        ("dst_ip",            "Dest IP",        "text"),
        ("orig_len",          "Packet Size",    "numeric"),
        ("payload_len",       "Payload Size",   "numeric"),
        ("dhcp_msg_type",     "DHCP Msg Type",  "text"),
        ("dhcp_hostname",     "Hostname",       "text"),
        ("dhcp_vendor_class", "Vendor Class",   "text"),
        ("dhcp_offered_ip",   "Offered IP",     "text"),
        ("dhcp_lease_time",   "Lease Time (s)", "numeric"),
    ],
    "arp": [
        ("timestamp",       "Time",        "time"),
        ("src_ip",          "Source IP",   "text"),
        ("dst_ip",          "Dest IP",     "text"),
        ("orig_len",        "Packet Size", "numeric"),
        ("arp_opcode_name", "Opcode",      "text"),
        ("arp_src_mac",     "Sender MAC",  "text"),
    ],
    "icmp": [
        ("timestamp",  "Time",        "time"),
        ("src_ip",     "Source IP",   "text"),
        ("dst_ip",     "Dest IP",     "text"),
        ("orig_len",   "Packet Size", "numeric"),
        ("payload_len","Payload Size","numeric"),
        ("icmp_type",  "ICMP Type",   "numeric"),
        ("icmp_code",  "ICMP Code",   "numeric"),
    ],
}

# Protocol filters used both for has_data checks and row extraction
_PROTOCOL_FILTERS = {
    "dns":  lambda p: "DNS"  in (p.protocol or "").upper() or bool(p.extra.get("dns_query")),
    "http": lambda p: "HTTP" in (p.protocol or "").upper() or bool(p.extra.get("http_method") or p.extra.get("http_status")),
    "tls":  lambda p: "TLS"  in (p.protocol or "").upper() or bool(p.extra.get("tls_sni") or p.extra.get("tls_record_version")),
    "tcp":  lambda p: p.transport == "TCP",
    "dhcp": lambda p: "DHCP" in (p.protocol or "").upper() or bool(p.extra.get("dhcp_msg_type")),
    "arp":  lambda p: p.protocol == "ARP" or bool(p.extra.get("arp_opcode_name")),
    "icmp": lambda p: p.transport in ("ICMP", "ICMPv6") or p.icmp_type >= 0,
}


def _infer_type(value: Any) -> str:
    """Guess value_type from a scalar value."""
    if isinstance(value, bool):
        return "text"
    if isinstance(value, (int, float)):
        return "numeric"
    return "text"


def _humanise(key: str) -> str:
    """Turn a snake_case extra key into a readable label."""
    return key.replace("_", " ").title()


def _discover_extra_fields(source: str, packets, max_scan: int = 500) -> List[tuple]:
    """
    Scan up to max_scan matching packets and return extra fields not already
    in SOURCE_FIELDS[source] as (name, label, type) tuples.

    Only scalar values (str / int / float / bool) are included.
    Lists, dicts, bytes, and None are skipped.
    """
    known = {f[0] for f in SOURCE_FIELDS.get(source, [])}
    filt = _PROTOCOL_FILTERS.get(source)

    discovered: Dict[str, str] = {}  # name → inferred type
    scanned = 0

    for p in packets:
        if filt and not filt(p):
            continue
        for k, v in p.extra.items():
            if k in known or k in discovered:
                continue
            if v is None or isinstance(v, (list, dict, bytes)):
                continue
            discovered[k] = _infer_type(v)
        scanned += 1
        if scanned >= max_scan:
            break

    return [(k, _humanise(k), t) for k, t in sorted(discovered.items())]


def _discover_session_fields(sessions, max_scan: int = 200) -> List[tuple]:
    """
    Scan sessions for keys not in SOURCE_FIELDS['sessions'] and return extras.
    Useful when protocol_fields/*.py accumulate additional session keys.
    """
    known = {f[0] for f in SOURCE_FIELDS["sessions"]}
    discovered: Dict[str, str] = {}
    for s in sessions[:max_scan]:
        for k, v in s.items():
            if k in known or k in discovered or k.startswith("_"):
                continue
            if v is None or isinstance(v, (list, dict, bytes)):
                continue
            discovered[k] = _infer_type(v)
    return [(k, _humanise(k), t) for k, t in sorted(discovered.items())]


def sources_info(packets=None, sessions=None) -> List[Dict[str, Any]]:
    """
    Return source metadata for the frontend schema endpoint.

    When packets/sessions are provided, dynamically appends any extra fields
    found in actual capture data that are not in the static baseline.
    This makes the field list self-describing — new dissectors auto-appear.
    """
    result = []
    for slug in SOURCE_LABELS:
        base = list(SOURCE_FIELDS[slug])
        if packets:
            if slug == "sessions":
                extras = _discover_session_fields(sessions or [])
            else:
                extras = _discover_extra_fields(slug, packets)
            base = base + extras
        result.append({
            "id":     slug,
            "label":  SOURCE_LABELS[slug],
            "fields": [{"name": f[0], "label": f[1], "type": f[2]} for f in base],
        })
    return result


# ── Data presence check ───────────────────────────────────────────────────────

def source_has_data(source: str, packets, sessions) -> bool:
    """Quick check: does the current capture contain data for this source?"""
    if source == "packets":
        return bool(packets)
    if source == "sessions":
        return bool(sessions)
    check = _PROTOCOL_FILTERS.get(source)
    if not check:
        return False
    return any(check(p) for p in packets)


# ── Data extraction per source ────────────────────────────────────────────────

def _extract_packets(packets, source: str) -> List[Dict[str, Any]]:
    """
    Extract rows from packets for the given source filter.
    Base packet fields are always included; pkt.extra is merged on top.
    """
    filt = _PROTOCOL_FILTERS.get(source)
    rows = []
    for p in packets:
        if filt and not filt(p):
            continue
        row: Dict[str, Any] = {
            "timestamp":    p.timestamp,
            "src_ip":       p.src_ip,
            "dst_ip":       p.dst_ip,
            "src_port":     p.src_port,
            "dst_port":     p.dst_port,
            "protocol":     p.protocol,
            "transport":    p.transport,
            "orig_len":     p.orig_len,
            "payload_len":  p.payload_len,
            "ttl":          p.ttl,
            "ip_version":   p.ip_version,
            "tcp_flags_str":p.tcp_flags_str,
            "seq_num":      p.seq_num,
            "ack_num":      p.ack_num,
            "window_size":  p.window_size,
            "icmp_type":    p.icmp_type if p.icmp_type >= 0 else None,
            "icmp_code":    p.icmp_code if p.icmp_code >= 0 else None,
        }
        row.update(p.extra)
        rows.append(row)
    return rows


def _extract_sessions(sessions) -> List[Dict[str, Any]]:
    return [dict(s) for s in sessions]


def extract_rows(source: str, packets, sessions) -> List[Dict[str, Any]]:
    if source == "sessions":
        return _extract_sessions(sessions)
    return _extract_packets(packets, source if source != "packets" else None)


# ── Figure builder ────────────────────────────────────────────────────────────

def _field_values(rows: List[Dict], field: str) -> List[Any]:
    return [r.get(field) for r in rows]


def _hover_text(rows: List[Dict], hover_fields: List[str]) -> List[str]:
    if not hover_fields:
        return []
    texts = []
    for r in rows:
        parts = []
        for f in hover_fields:
            v = r.get(f)
            if v is not None and v != "":
                parts.append(f"{f}: {v}")
        texts.append("<br>".join(parts))
    return texts


def build_figure(payload: Dict[str, Any], packets, sessions) -> Dict[str, Any]:
    """
    Build a Plotly figure dict from a field-mapping payload.
    """
    source      = payload.get("source", "packets")
    chart_type  = payload.get("chart_type", "scatter")
    x_field     = payload.get("x_field", "")
    y_field     = payload.get("y_field", "")
    color_field = payload.get("color_field") or None
    size_field  = payload.get("size_field")  or None
    hover_fields= payload.get("hover_fields", [])
    title       = payload.get("title", "Custom Chart")

    rows = extract_rows(source, packets, sessions)

    if not rows:
        fig = go.Figure()
        fig.update_layout({**SWIFTEYE_LAYOUT, "title": {"text": f"{title} — no data for source '{source}'"}})
        return fig.to_dict()

    x_vals = _field_values(rows, x_field)
    hover  = _hover_text(rows, hover_fields)

    layout_overrides = {
        "title": {"text": title, "font": {"size": 13}},
        "xaxis": {"title": {"text": x_field}},
        "yaxis": {"title": {"text": y_field or "count"}},
        "margin": {"l": 50, "r": 20, "t": 40, "b": 50},
    }

    if chart_type == "histogram":
        if color_field:
            color_vals = _field_values(rows, color_field)
            unique_colors = list(dict.fromkeys(str(v) for v in color_vals if v is not None))[:20]
            traces = []
            for cv in unique_colors:
                mask = [str(r.get(color_field)) == cv for r in rows]
                traces.append(go.Histogram(
                    x=[v for v, m in zip(x_vals, mask) if m],
                    name=cv,
                    opacity=0.75,
                ))
            fig = go.Figure(data=traces)
            fig.update_layout(barmode="overlay")
        else:
            fig = go.Figure(data=[go.Histogram(x=x_vals)])

    elif chart_type == "bar":
        y_vals = _field_values(rows, y_field) if y_field else [1] * len(rows)
        marker_kw: Dict[str, Any] = {}
        if color_field:
            color_vals = _field_values(rows, color_field)
            marker_kw["color"] = [v if v is not None else "" for v in color_vals]
        trace = go.Bar(
            x=x_vals,
            y=y_vals,
            text=hover if hover else None,
            hoverinfo="text" if hover else "x+y",
            marker=marker_kw if marker_kw else None,
        )
        fig = go.Figure(data=[trace])

    else:  # scatter (default)
        y_vals = _field_values(rows, y_field) if y_field else [None] * len(rows)
        marker_kw_: Dict[str, Any] = {"size": 6, "opacity": 0.7}
        if color_field:
            color_vals = _field_values(rows, color_field)
            marker_kw_["color"] = [v if v is not None else "" for v in color_vals]
            if color_vals and isinstance(color_vals[0], (int, float)):
                marker_kw_["colorscale"] = "Viridis"
                marker_kw_["showscale"] = True
        if size_field:
            raw_sizes = _field_values(rows, size_field)
            nums = [s for s in raw_sizes if isinstance(s, (int, float)) and s is not None]
            if nums:
                mn, mx = min(nums), max(nums)
                rng = mx - mn or 1
                marker_kw_["size"] = [
                    3 + 17 * (s - mn) / rng if isinstance(s, (int, float)) and s is not None else 6
                    for s in raw_sizes
                ]
        trace = go.Scatter(
            x=x_vals,
            y=y_vals,
            mode="markers",
            text=hover if hover else None,
            hoverinfo="text" if hover else "x+y",
            marker=marker_kw_,
        )
        fig = go.Figure(data=[trace])

    fig.update_layout({**SWIFTEYE_LAYOUT, **layout_overrides})
    return fig.to_dict()
