"""
Custom research chart — ad-hoc Plotly figures built from the Research panel UI.

The frontend sends a field-mapping payload; this module extracts the data from
the current capture (packets or sessions) and returns a Plotly figure dict.

== Payload schema ==

  {
    "source":       <source slug>,
    "chart_type":   "scatter" | "bar" | "histogram",
    "x_field":      "<field name>",
    "y_field":      "<field name>",           # omitted for histogram (x is the value)
    "color_field":  "<field name>" | null,
    "size_field":   "<field name>" | null,     # scatter only
    "hover_fields": ["<field>", ...],
    "title":        "<chart title>",
  }

== Source discovery ==

  sources_info(packets, sessions) builds the source list dynamically:

  1. Static sources: packets, sessions, dns, http, tls, tcp, dhcp, arp, icmp
     — always present, with curated baseline fields + dynamic extra discovery.

  2. Dynamic protocol sources: any protocol value found in the capture that is
     NOT already covered by a static source gets its own card automatically.
     E.g. if the capture has SMB or Kerberos traffic, "SMB" and "Kerberos"
     appear as sources with fields entirely discovered from pkt.extra.

== Field discovery ==

  SOURCE_FIELDS defines the known baseline fields per static source.
  Additionally, _discover_extra_fields scans a sample of matching packets and
  appends any pkt.extra keys not already in the static list.  New dissectors
  auto-appear without registration — the architecture is self-describing.

  Only scalar values (str / int / float / bool) become fields.
  Lists, dicts, and bytes are skipped.

== Colour handling ==

  Plotly's marker.color accepts numeric arrays (colourscale) or valid CSS colour
  strings — NOT arbitrary text.  When a text field is chosen as colour we instead
  split into one trace per unique category value (max 20), which gives a proper
  categorical legend and works for all chart types.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

try:
    import plotly.graph_objects as go
    _PLOTLY_AVAILABLE = True
except ImportError:
    go = None  # type: ignore[assignment]
    _PLOTLY_AVAILABLE = False


logger = logging.getLogger("swifteye.research.custom")

# ── Static source definitions ─────────────────────────────────────────────────

# Slugs that have dedicated filter logic and curated baseline fields.
# Any protocol NOT in this set gets auto-discovered as a dynamic source.
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

# Baseline fields per static source — (field_name, human_label, value_type)
# value_type: "numeric" | "text" | "time"
#
# Base packet fields (orig_len, payload_len, src_ip, dst_ip, timestamp) are
# included in ALL packet-based sources because _extract_packets always
# populates them regardless of which protocol filter is active.
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

# Protocol filters for static sources — used for has_data checks and row filtering
_PROTOCOL_FILTERS = {
    "dns":  lambda p: "DNS"  in (p.protocol or "").upper() or bool(p.extra.get("dns_query")),
    "http": lambda p: "HTTP" in (p.protocol or "").upper() or bool(p.extra.get("http_method") or p.extra.get("http_status")),
    "tls":  lambda p: "TLS"  in (p.protocol or "").upper() or bool(p.extra.get("tls_sni") or p.extra.get("tls_record_version")),
    "tcp":  lambda p: p.transport == "TCP",
    "dhcp": lambda p: "DHCP" in (p.protocol or "").upper() or bool(p.extra.get("dhcp_msg_type")),
    "arp":  lambda p: p.protocol == "ARP" or bool(p.extra.get("arp_opcode_name")),
    "icmp": lambda p: p.transport in ("ICMP", "ICMPv6") or p.icmp_type >= 0,
}

# Protocols covered by static sources — used to skip them in dynamic discovery
_STATIC_PROTOCOL_NAMES: Set[str] = {
    "DNS", "MDNS", "LLMNR",
    "HTTP", "HTTPS", "HTTP-ALT", "HTTP-ALT2", "HTTP-ALT3", "HTTP-DEV", "HTTP-DEV2", "HTTP-MGMT",
    "TLS", "QUIC",
    "TCP",
    "DHCP",
    "ARP",
    "ICMP", "ICMPV6",
    "UDP",  # too generic to be its own source; captured by protocol-specific sources
}


# ── Field discovery helpers ───────────────────────────────────────────────────

def _infer_type(value: Any) -> str:
    if isinstance(value, bool):
        return "text"
    if isinstance(value, (int, float)):
        return "numeric"
    return "text"


def _humanise(key: str) -> str:
    return key.replace("_", " ").title()


# Base packet fields always included in every packet-source row
_BASE_PACKET_FIELDS: List[tuple] = [
    ("timestamp",    "Time",          "time"),
    ("src_ip",       "Source IP",     "text"),
    ("dst_ip",       "Dest IP",       "text"),
    ("src_port",     "Source Port",   "numeric"),
    ("dst_port",     "Dest Port",     "numeric"),
    ("protocol",     "Protocol",      "text"),
    ("transport",    "Transport",     "text"),
    ("orig_len",     "Packet Size",   "numeric"),
    ("payload_len",  "Payload Size",  "numeric"),
    ("ttl",          "TTL",           "numeric"),
]


def _discover_extra_fields(
    source: str, packets, known_names: set = None, max_scan: int = 500
) -> List[tuple]:
    """
    Scan up to max_scan matching packets and return extra fields not already
    in known_names as (name, label, type) tuples.
    Only scalar values are included — lists, dicts, bytes, None are skipped.
    """
    if known_names is None:
        known_names = {f[0] for f in SOURCE_FIELDS.get(source, [])}
    filt = _PROTOCOL_FILTERS.get(source)
    # For dynamic protocol sources the filter is a protocol-name equality check
    if filt is None and source not in ("packets", "sessions"):
        proto_upper = source.upper()
        filt = lambda p: (p.protocol or "").upper() == proto_upper

    discovered: Dict[str, str] = {}
    scanned = 0
    for p in packets:
        if filt and not filt(p):
            continue
        for k, v in p.extra.items():
            if k in known_names or k in discovered:
                continue
            if v is None or isinstance(v, (list, dict, bytes)):
                continue
            discovered[k] = _infer_type(v)
        scanned += 1
        if scanned >= max_scan:
            break
    return [(k, _humanise(k), t) for k, t in sorted(discovered.items())]


def _discover_session_fields(sessions, max_scan: int = 200) -> List[tuple]:
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


def _dynamic_protocol_sources(packets) -> List[Dict[str, Any]]:
    """
    Scan all packets and return source dicts for any protocol not covered by
    a static source.  Each dynamic source gets the base packet fields plus
    whatever extra keys are found in packets of that protocol.
    """
    if not packets:
        return []

    # Collect unique protocol names not already handled
    seen: Dict[str, int] = {}  # protocol → packet count
    for p in packets:
        proto = (p.protocol or "").strip()
        if proto and proto.upper() not in _STATIC_PROTOCOL_NAMES:
            seen[proto] = seen.get(proto, 0) + 1

    if not seen:
        return []

    base_names = {f[0] for f in _BASE_PACKET_FIELDS}
    result = []
    for proto in sorted(seen.keys()):
        extras = _discover_extra_fields(proto, packets, known_names=set(base_names))
        fields = list(_BASE_PACKET_FIELDS) + extras
        result.append({
            "id":    proto,
            "label": proto,
            "fields": [{"name": f[0], "label": f[1], "type": f[2]} for f in fields],
            "_dynamic": True,
        })
    return result


# ── Public API ────────────────────────────────────────────────────────────────

def sources_info(packets=None, sessions=None) -> List[Dict[str, Any]]:
    """
    Return source metadata for the frontend schema endpoint.

    Builds the static sources (with dynamic extra-field discovery) and appends
    any dynamic protocol sources discovered from the actual capture.
    """
    result = []
    for slug in SOURCE_LABELS:
        base = list(SOURCE_FIELDS[slug])
        if packets:
            if slug == "sessions":
                extras = _discover_session_fields(sessions or [])
            else:
                known = {f[0] for f in base}
                extras = _discover_extra_fields(slug, packets, known_names=known)
            base = base + extras
        result.append({
            "id":     slug,
            "label":  SOURCE_LABELS[slug],
            "fields": [{"name": f[0], "label": f[1], "type": f[2]} for f in base],
        })

    # Append dynamic protocol sources (e.g. SMB, Kerberos, QUIC, ...)
    if packets:
        result.extend(_dynamic_protocol_sources(packets))

    return result


def source_has_data(source: str, packets, sessions) -> bool:
    if source == "packets":
        return bool(packets)
    if source == "sessions":
        return bool(sessions)
    check = _PROTOCOL_FILTERS.get(source)
    if check:
        return any(check(p) for p in packets)
    # Dynamic protocol source
    proto_upper = source.upper()
    return any((p.protocol or "").upper() == proto_upper for p in packets)


# ── Data extraction ───────────────────────────────────────────────────────────

def _extract_packets(packets, source: str) -> List[Dict[str, Any]]:
    """
    Extract rows from packets for the given source filter.
    Base packet fields are always included; pkt.extra is merged on top.
    """
    filt = _PROTOCOL_FILTERS.get(source)
    if filt is None and source not in ("packets", "sessions", None):
        proto_upper = source.upper()
        filt = lambda p: (p.protocol or "").upper() == proto_upper

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


def _to_datetime_series(vals: List[Any]) -> List[Any]:
    """Convert a list of Unix-epoch floats to ISO-8601 strings for Plotly datetime axes.
    Non-numeric values are passed through unchanged."""
    result = []
    for v in vals:
        if isinstance(v, (int, float)) and v is not None:
            try:
                result.append(datetime.fromtimestamp(v, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
            except (OSError, OverflowError, ValueError):
                result.append(v)
        else:
            result.append(v)
    return result


def _hover_text(rows: List[Dict], hover_fields: List[str]) -> List[str]:
    if not hover_fields:
        return []
    texts = []
    for r in rows:
        parts = [f"{f}: {r[f]}" for f in hover_fields if r.get(f) not in (None, "")]
        texts.append("<br>".join(parts))
    return texts


def _is_numeric_series(vals: List[Any]) -> bool:
    """True if the first non-None value in the series is numeric."""
    for v in vals:
        if v is not None:
            return isinstance(v, (int, float)) and not isinstance(v, bool)
    return False


def _split_traces_by_color(rows, x_field, y_field, color_field, hover, chart_type):
    """
    Build multiple traces, one per unique value of color_field (max 20).
    Used for text-valued colour fields — Plotly can't use arbitrary strings
    as marker colours directly.
    Returns a list of Plotly trace objects.
    """
    unique_vals = list(dict.fromkeys(
        str(r.get(color_field, "")) for r in rows
    ))[:20]

    traces = []
    for cv in unique_vals:
        group = [r for r in rows if str(r.get(color_field, "")) == cv]
        x = [r.get(x_field) for r in group]
        hover_t = [
            "<br>".join(f"{f}: {r[f]}" for f in (hover if isinstance(hover, list) else [])
                        if r.get(f) not in (None, ""))
            for r in group
        ] if hover else None

        if chart_type == "histogram":
            traces.append(go.Histogram(x=x, name=cv, opacity=0.75))
        elif chart_type == "bar":
            y = [r.get(y_field) for r in group]
            traces.append(go.Bar(
                x=x, y=y, name=cv,
                text=hover_t, hoverinfo="text" if hover_t else "x+y",
            ))
        else:  # scatter
            y = [r.get(y_field) for r in group]
            traces.append(go.Scatter(
                x=x, y=y, mode="markers", name=cv,
                text=hover_t, hoverinfo="text" if hover_t else "x+y",
                marker={"size": 6, "opacity": 0.7},
            ))
    return traces


def build_figure(payload: Dict[str, Any], packets, sessions):
    if not _PLOTLY_AVAILABLE:
        raise RuntimeError("plotly is not installed — custom charts unavailable. pip install plotly")
    source       = payload.get("source", "packets")
    chart_type   = payload.get("chart_type", "scatter")
    x_field      = payload.get("x_field", "")
    y_field      = payload.get("y_field", "")
    color_field  = payload.get("color_field") or None
    size_field   = payload.get("size_field")  or None
    hover_fields = payload.get("hover_fields", [])
    title        = payload.get("title", "Custom Chart")

    rows = extract_rows(source, packets, sessions)

    if not rows:
        fig = go.Figure()
        fig.update_layout({"title": {"text": f"{title} — no data for source '{source}'"}})
        return fig

    x_vals = _field_values(rows, x_field)
    if x_field == "timestamp":
        x_vals = _to_datetime_series(x_vals)
    hover  = _hover_text(rows, hover_fields)

    layout_overrides = {
        "title":  {"text": title, "font": {"size": 13}},
        "xaxis":  {"title": {"text": x_field}},
        "yaxis":  {"title": {"text": y_field or "count"}},
        "margin": {"l": 50, "r": 20, "t": 40, "b": 50},
    }

    # Determine if colour field is numeric (colorscale) or text (split traces)
    color_is_numeric = False
    if color_field:
        color_vals = _field_values(rows, color_field)
        color_is_numeric = _is_numeric_series(color_vals)

    # ── Histogram ──────────────────────────────────────────────────────────────
    if chart_type == "histogram":
        if color_field:
            if color_is_numeric:
                fig = go.Figure(data=[go.Histogram(x=x_vals)])
            else:
                traces = _split_traces_by_color(rows, x_field, y_field, color_field, None, "histogram")
                fig = go.Figure(data=traces)
                layout_overrides["barmode"] = "overlay"
        else:
            fig = go.Figure(data=[go.Histogram(x=x_vals)])

    # ── Bar ────────────────────────────────────────────────────────────────────
    elif chart_type == "bar":
        y_vals = _field_values(rows, y_field) if y_field else [1] * len(rows)
        if y_field == "timestamp":
            y_vals = _to_datetime_series(y_vals)
        if color_field:
            if color_is_numeric:
                color_vals = _field_values(rows, color_field)
                trace = go.Bar(
                    x=x_vals, y=y_vals,
                    text=hover if hover else None,
                    hoverinfo="text" if hover else "x+y",
                    marker={"color": [v if v is not None else 0 for v in color_vals],
                            "colorscale": "Viridis", "showscale": True},
                )
                fig = go.Figure(data=[trace])
            else:
                traces = _split_traces_by_color(rows, x_field, y_field, color_field, hover_fields, "bar")
                fig = go.Figure(data=traces)
        else:
            trace = go.Bar(
                x=x_vals, y=y_vals,
                text=hover if hover else None,
                hoverinfo="text" if hover else "x+y",
            )
            fig = go.Figure(data=[trace])

    # ── Scatter ────────────────────────────────────────────────────────────────
    else:
        y_vals = _field_values(rows, y_field) if y_field else [None] * len(rows)
        if y_field == "timestamp":
            y_vals = _to_datetime_series(y_vals)

        if color_field:
            if color_is_numeric:
                color_vals = _field_values(rows, color_field)
                marker: Dict[str, Any] = {
                    "size": 6, "opacity": 0.7,
                    "color": [v if v is not None else float("nan") for v in color_vals],
                    "colorscale": "Viridis", "showscale": True,
                }
                if size_field:
                    raw_sizes = _field_values(rows, size_field)
                    nums = [s for s in raw_sizes if isinstance(s, (int, float)) and s is not None]
                    if nums:
                        mn, mx = min(nums), max(nums)
                        rng = mx - mn or 1
                        marker["size"] = [
                            3 + 17 * (s - mn) / rng if isinstance(s, (int, float)) and s is not None else 6
                            for s in raw_sizes
                        ]
                fig = go.Figure(data=[go.Scatter(
                    x=x_vals, y=y_vals, mode="markers",
                    text=hover if hover else None,
                    hoverinfo="text" if hover else "x+y",
                    marker=marker,
                )])
            else:
                # Text colour → split into per-category traces
                traces = _split_traces_by_color(rows, x_field, y_field, color_field, hover_fields, "scatter")
                # size_field per split-trace would need group-aware sizing; skip for now
                fig = go.Figure(data=traces)
        else:
            marker_: Dict[str, Any] = {"size": 6, "opacity": 0.7}
            if size_field:
                raw_sizes = _field_values(rows, size_field)
                nums = [s for s in raw_sizes if isinstance(s, (int, float)) and s is not None]
                if nums:
                    mn, mx = min(nums), max(nums)
                    rng = mx - mn or 1
                    marker_["size"] = [
                        3 + 17 * (s - mn) / rng if isinstance(s, (int, float)) and s is not None else 6
                        for s in raw_sizes
                    ]
            fig = go.Figure(data=[go.Scatter(
                x=x_vals, y=y_vals, mode="markers",
                text=hover if hover else None,
                hoverinfo="text" if hover else "x+y",
                marker=marker_,
            )])

    # When colour produces categorical traces the labels can be arbitrarily long
    # (e.g. full User-Agent strings). Move the legend below the chart so it
    # doesn't crush the plot area. Numeric colour uses a colourscale/colorbar
    # instead of a legend, so no adjustment is needed there.
    if color_field and not color_is_numeric:
        layout_overrides["legend"] = {
            "orientation": "h",
            "yanchor": "top",
            "y": -0.15,
            "xanchor": "left",
            "x": 0,
        }
        layout_overrides["margin"]["b"] = 120

    fig.update_layout(layout_overrides)
    return fig
