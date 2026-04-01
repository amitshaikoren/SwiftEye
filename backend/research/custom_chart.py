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

== Available sources and their fields ==

  packets   — timestamp, src_ip, dst_ip, src_port, dst_port, protocol, transport,
               orig_len, payload_len, ttl, ip_version, tcp_flags_str, seq_num, ack_num,
               window_size, icmp_type, icmp_code
  sessions  — start_time, end_time, duration, src_ip, dst_ip, src_port, dst_port,
               protocol, transport, total_bytes, payload_bytes, packet_count
  dns       — timestamp, src_ip, dst_ip, dns_query, dns_qtype_name, dns_rcode_name,
               dns_ancount, dns_qr
  http      — timestamp, src_ip, dst_ip, http_method, http_uri, http_host,
               http_status, http_user_agent, http_content_length
  tls       — timestamp, src_ip, dst_ip, tls_sni, tls_record_version, tls_msg_type, ja3
  tcp       — timestamp, src_ip, dst_ip, src_port, dst_port, tcp_flags_str,
               seq_num, ack_num, window_size, orig_len
  dhcp      — timestamp, src_ip, dst_ip, dhcp_msg_type, dhcp_hostname,
               dhcp_vendor_class, dhcp_offered_ip, dhcp_lease_time
  arp       — timestamp, src_ip, dst_ip, arp_opcode_name, arp_src_mac
  icmp      — timestamp, src_ip, dst_ip, icmp_type, icmp_code, orig_len
"""

import logging
from typing import Any, Dict, List, Optional

import plotly.graph_objects as go

from constants import SWIFTEYE_LAYOUT

logger = logging.getLogger("swifteye.research.custom")

# ── Source definitions ────────────────────────────────────────────────────────

# Maps source slug → human label
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

# Fields available per source — (field_name, human_label, value_type)
# value_type: "numeric" | "text" | "time"
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
        ("timestamp",      "Time",         "time"),
        ("src_ip",         "Source IP",    "text"),
        ("dst_ip",         "Dest IP",      "text"),
        ("dns_query",      "Query Name",   "text"),
        ("dns_qtype_name", "Query Type",   "text"),
        ("dns_rcode_name", "Response Code","text"),
        ("dns_ancount",    "Answer Count", "numeric"),
        ("dns_qr",         "QR",           "text"),
    ],
    "http": [
        ("timestamp",            "Time",           "time"),
        ("src_ip",               "Source IP",      "text"),
        ("dst_ip",               "Dest IP",        "text"),
        ("http_method",          "Method",         "text"),
        ("http_uri",             "URI",            "text"),
        ("http_host",            "Host",           "text"),
        ("http_status",          "Status Code",    "numeric"),
        ("http_user_agent",      "User-Agent",     "text"),
        ("http_content_length",  "Content-Length", "numeric"),
    ],
    "tls": [
        ("timestamp",           "Time",        "time"),
        ("src_ip",              "Source IP",   "text"),
        ("dst_ip",              "Dest IP",     "text"),
        ("tls_sni",             "SNI",         "text"),
        ("tls_record_version",  "TLS Version", "text"),
        ("tls_msg_type",        "Msg Type",    "text"),
        ("ja3",                 "JA3 Hash",    "text"),
    ],
    "tcp": [
        ("timestamp",    "Time",        "time"),
        ("src_ip",       "Source IP",   "text"),
        ("dst_ip",       "Dest IP",     "text"),
        ("src_port",     "Source Port", "numeric"),
        ("dst_port",     "Dest Port",   "numeric"),
        ("tcp_flags_str","TCP Flags",   "text"),
        ("seq_num",      "Seq Num",     "numeric"),
        ("ack_num",      "Ack Num",     "numeric"),
        ("window_size",  "Window Size", "numeric"),
        ("orig_len",     "Packet Size", "numeric"),
    ],
    "dhcp": [
        ("timestamp",          "Time",           "time"),
        ("src_ip",             "Source IP",      "text"),
        ("dst_ip",             "Dest IP",        "text"),
        ("dhcp_msg_type",      "DHCP Msg Type",  "text"),
        ("dhcp_hostname",      "Hostname",       "text"),
        ("dhcp_vendor_class",  "Vendor Class",   "text"),
        ("dhcp_offered_ip",    "Offered IP",     "text"),
        ("dhcp_lease_time",    "Lease Time (s)", "numeric"),
    ],
    "arp": [
        ("timestamp",       "Time",       "time"),
        ("src_ip",          "Source IP",  "text"),
        ("dst_ip",          "Dest IP",    "text"),
        ("arp_opcode_name", "Opcode",     "text"),
        ("arp_src_mac",     "Sender MAC", "text"),
    ],
    "icmp": [
        ("timestamp",  "Time",        "time"),
        ("src_ip",     "Source IP",   "text"),
        ("dst_ip",     "Dest IP",     "text"),
        ("icmp_type",  "ICMP Type",   "numeric"),
        ("icmp_code",  "ICMP Code",   "numeric"),
        ("orig_len",   "Packet Size", "numeric"),
    ],
}


def sources_info() -> List[Dict[str, Any]]:
    """Return source metadata for the frontend schema endpoint."""
    return [
        {
            "id":     slug,
            "label":  SOURCE_LABELS[slug],
            "fields": [
                {"name": f[0], "label": f[1], "type": f[2]}
                for f in SOURCE_FIELDS[slug]
            ],
        }
        for slug in SOURCE_LABELS
    ]


# ── Data extraction per source ────────────────────────────────────────────────

def _extract_packets(packets, source: str) -> List[Dict[str, Any]]:
    """
    Extract rows from packets for the given source filter.
    Returns a list of flat dicts keyed by the field names in SOURCE_FIELDS[source].
    """
    rows = []
    protocol_filter = {
        "dns":  lambda p: "DNS"  in (p.protocol or "").upper() or p.extra.get("dns_query"),
        "http": lambda p: "HTTP" in (p.protocol or "").upper() or p.extra.get("http_method") or p.extra.get("http_status"),
        "tls":  lambda p: "TLS"  in (p.protocol or "").upper() or p.extra.get("tls_sni") or p.extra.get("tls_record_version"),
        "tcp":  lambda p: p.transport == "TCP",
        "dhcp": lambda p: "DHCP" in (p.protocol or "").upper() or p.extra.get("dhcp_msg_type"),
        "arp":  lambda p: p.protocol == "ARP" or p.extra.get("arp_opcode_name"),
        "icmp": lambda p: p.transport in ("ICMP", "ICMPv6") or p.icmp_type >= 0,
    }

    filt = protocol_filter.get(source)

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
        # Merge extra fields
        row.update(p.extra)
        rows.append(row)

    return rows


def _extract_sessions(sessions) -> List[Dict[str, Any]]:
    return [
        {
            "start_time":   s.get("start_time"),
            "end_time":     s.get("end_time"),
            "duration":     s.get("duration", 0),
            "src_ip":       s.get("src_ip", ""),
            "dst_ip":       s.get("dst_ip", ""),
            "src_port":     s.get("src_port", 0),
            "dst_port":     s.get("dst_port", 0),
            "protocol":     s.get("protocol", ""),
            "transport":    s.get("transport", ""),
            "total_bytes":  s.get("total_bytes", 0),
            "payload_bytes":s.get("payload_bytes", 0),
            "packet_count": s.get("packet_count", 0),
        }
        for s in sessions
    ]


def extract_rows(source: str, packets, sessions) -> List[Dict[str, Any]]:
    if source == "sessions":
        return _extract_sessions(sessions)
    return _extract_packets(packets, source if source != "packets" else None)


# ── Data presence check ───────────────────────────────────────────────────────

def source_has_data(source: str, packets, sessions) -> bool:
    """Quick check: does the current capture contain data for this source?"""
    if source == "packets":
        return bool(packets)
    if source == "sessions":
        return bool(sessions)

    checkers = {
        "dns":  lambda p: "DNS"  in (p.protocol or "").upper() or bool(p.extra.get("dns_query")),
        "http": lambda p: "HTTP" in (p.protocol or "").upper() or bool(p.extra.get("http_method") or p.extra.get("http_status")),
        "tls":  lambda p: "TLS"  in (p.protocol or "").upper() or bool(p.extra.get("tls_sni")),
        "tcp":  lambda p: p.transport == "TCP",
        "dhcp": lambda p: "DHCP" in (p.protocol or "").upper() or bool(p.extra.get("dhcp_msg_type")),
        "arp":  lambda p: p.protocol == "ARP" or bool(p.extra.get("arp_opcode_name")),
        "icmp": lambda p: p.transport in ("ICMP", "ICMPv6") or p.icmp_type >= 0,
    }
    check = checkers.get(source)
    if not check:
        return False
    return any(check(p) for p in packets)


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

    payload keys: source, chart_type, x_field, y_field (optional for histogram),
                  color_field, size_field, hover_fields, title
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
        marker_kw = {}
        if color_field:
            color_vals = _field_values(rows, color_field)
            # Histogram doesn't support per-point color the same way — use color as
            # a grouping axis and produce one trace per unique value (up to 20).
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
            fig = go.Figure(data=[go.Histogram(x=x_vals, **marker_kw)])

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
            # numeric color → colorscale; text → leave as category colors
            if color_vals and isinstance(color_vals[0], (int, float)):
                marker_kw_["colorscale"] = "Viridis"
                marker_kw_["showscale"] = True
        if size_field:
            raw_sizes = _field_values(rows, size_field)
            # Normalise to 3–20px range
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
