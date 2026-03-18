"""
HTTP User-Agent Timeline — Research Chart

Question answered:
    Which source IPs made HTTP requests, when, and with what User-Agent?

Chart type:
    Scatter plot. X = time. Y = source IP (categorical, one row per unique IP).
    Colour = User-Agent string (one legend entry per unique UA).
    Dot size = request payload bytes (capped, minimum visible).

Useful for:
    - Spotting automated tools: curl, python-requests, PowerShell UA strings
    - Identifying C2 beaconing: same UA hitting the same host at intervals
    - UA spoofing: a machine using a browser-like UA for scripted requests
    - Lateral movement: internal IPs suddenly issuing HTTP requests
    - Correlating with DNS: which host resolved a domain, then POSTed to it
"""

from collections import defaultdict
from research import ResearchChart, Param, AnalysisContext, SWIFTEYE_LAYOUT


# Colour palette — visually distinct, dark-theme friendly
_PALETTE = [
    "#58a6ff",  # blue
    "#3fb950",  # green
    "#f0883e",  # orange
    "#f85149",  # red
    "#bc8cff",  # purple
    "#39d353",  # lime
    "#db61a2",  # pink
    "#79c0ff",  # light blue
    "#d2a8ff",  # lavender
    "#f778ba",  # rose
    "#ffa657",  # peach
    "#7ee787",  # mint
    "#e3b341",  # gold
    "#56d4dd",  # teal
    "#ff7b72",  # salmon
]
_DEFAULT_COLOR = "#8b949e"  # no UA


def _shorten_ua(ua: str, max_len: int = 60) -> str:
    """Shorten a User-Agent string for legend/hover readability."""
    if len(ua) <= max_len:
        return ua
    return ua[:max_len - 1] + "…"


class HTTPUserAgentTimeline(ResearchChart):
    name        = "http_ua_timeline"
    title       = "HTTP User-Agent timeline"
    description = "HTTP requests over time — Y = source IP, colour = User-Agent. Spot scripted tools, C2 beacons, and UA spoofing."

    params = []  # No params — uses all HTTP packets in capture

    def compute(self, ctx: AnalysisContext, params: dict) -> dict:
        entries = []
        for pkt in ctx.packets:
            ex = pkt.extra
            # Only HTTP request packets (have a method)
            if not ex.get("http_method"):
                continue

            ua   = ex.get("http_user_agent", "")
            host = ex.get("http_host", "")
            uri  = ex.get("http_uri", "")
            method = ex.get("http_method", "")

            entries.append({
                "ts":     pkt.timestamp * 1000,  # ms for Plotly date axis
                "src":    pkt.src_ip,
                "dst":    pkt.dst_ip,
                "ua":     ua or "(no User-Agent)",
                "host":   host,
                "uri":    uri,
                "method": method,
                "bytes":  pkt.payload_len or pkt.orig_len or 0,
            })

        if not entries:
            return {
                "data": [],
                "layout": {
                    **SWIFTEYE_LAYOUT,
                    "title": {"text": "No HTTP request packets found in capture",
                              "font": {"color": "#8b949e"}},
                },
            }

        entries.sort(key=lambda e: e["ts"])

        # Unique source IPs sorted by first-seen time
        seen_ips = []
        seen_ip_set = set()
        for e in entries:
            if e["src"] not in seen_ip_set:
                seen_ips.append(e["src"])
                seen_ip_set.add(e["src"])

        # Unique UAs sorted by frequency (most common first for legend order)
        ua_counts = defaultdict(int)
        for e in entries:
            ua_counts[e["ua"]] += 1
        ua_sorted = sorted(ua_counts.keys(), key=lambda u: -ua_counts[u])

        # Assign colours
        ua_color = {}
        for i, ua in enumerate(ua_sorted):
            if ua == "(no User-Agent)":
                ua_color[ua] = _DEFAULT_COLOR
            else:
                ua_color[ua] = _PALETTE[i % len(_PALETTE)]

        # Build one trace per UA so legend is grouped
        trace_map = defaultdict(lambda: {"x": [], "y": [], "text": [], "sizes": []})

        for e in entries:
            ua = e["ua"]
            trace_map[ua]["x"].append(e["ts"])
            trace_map[ua]["y"].append(e["src"])
            # Dot size: scale by payload bytes, min 6, max 16
            sz = max(6, min(16, 6 + (e["bytes"] / 2000) * 10))
            trace_map[ua]["sizes"].append(sz)
            trace_map[ua]["text"].append(
                f"<b>{e['method']} {_shorten_ua(e['uri'], 80)}</b><br>"
                f"Host: {e['host'] or '—'}<br>"
                f"UA: {_shorten_ua(e['ua'], 120)}<br>"
                f"Source: {e['src']}<br>"
                f"Dest: {e['dst']}<br>"
                f"Bytes: {e['bytes']:,}"
            )

        # Build traces in frequency order
        traces = []
        for ua in ua_sorted:
            if ua not in trace_map:
                continue
            d = trace_map[ua]
            traces.append({
                "type": "scatter",
                "mode": "markers",
                "name": _shorten_ua(ua, 50),
                "x": d["x"],
                "y": d["y"],
                "text": d["text"],
                "hovertemplate": "%{text}<extra></extra>",
                "marker": {
                    "color": ua_color[ua],
                    "size": d["sizes"],
                    "opacity": 0.85,
                    "line": {"width": 0},
                },
            })

        height = max(300, 80 + len(seen_ips) * 28)

        layout = {
            **SWIFTEYE_LAYOUT,
            "title": {
                "text": f"HTTP User-Agent timeline · {len(entries)} requests · {len(seen_ips)} sources · {len(ua_sorted)} UAs",
                "font": {"color": "#e6edf3", "size": 12},
            },
            "xaxis": {
                **SWIFTEYE_LAYOUT["xaxis"],
                "title": {"text": "Time", "font": {"color": "#484f58"}},
                "type": "date",
                "tickformat": "%H:%M:%S",
            },
            "yaxis": {
                **SWIFTEYE_LAYOUT["yaxis"],
                "title": {"text": "Source IP", "font": {"color": "#484f58"}},
                "type": "category",
                "categoryorder": "array",
                "categoryarray": list(reversed(seen_ips)),  # newest at top
                "tickfont": {"size": 9, "family": "JetBrains Mono, monospace"},
                "automargin": True,
            },
            "height": height,
            "margin": {"l": 160, "r": 20, "t": 50, "b": 60},
            "legend": {
                "bgcolor":     "rgba(14,17,23,0.8)",
                "bordercolor": "rgba(48,54,61,0.8)",
                "borderwidth": 1,
                "font":        {"size": 9, "family": "JetBrains Mono, monospace"},
                "x": 1.01, "y": 1,
                "xanchor": "left", "yanchor": "top",
            },
        }

        return {"data": traces, "layout": layout}
