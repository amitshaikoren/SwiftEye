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
from typing import List

from workspaces.network.research import ResearchChart, Param, AnalysisContext, SWIFTEYE_LAYOUT


_PALETTE = [
    "#58a6ff", "#3fb950", "#f0883e", "#f85149", "#bc8cff",
    "#39d353", "#db61a2", "#79c0ff", "#d2a8ff", "#f778ba",
    "#ffa657", "#7ee787", "#e3b341", "#56d4dd", "#ff7b72",
]
_DEFAULT_COLOR = "#8b949e"


def _shorten(s: str, n: int = 60) -> str:
    return s if len(s) <= n else s[:n - 1] + "…"


class HTTPUserAgentTimeline(ResearchChart):
    name        = "http_ua_timeline"
    title       = "HTTP User-Agent timeline"
    description = "HTTP requests over time — Y = source IP, colour = User-Agent. Spot scripted tools, C2 beacons, and UA spoofing."
    category    = "capture"

    params = []
    entry_schema = {
        'src':    'ip',
        'dst':    'ip',
        'method': {'type': 'list', 'options': ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']},
        'host':   'string',
        'uri':    'string',
        'ua':     'string',
        'bytes':  'numeric',
    }

    def build_data(self, ctx: AnalysisContext, params: dict) -> List[dict]:
        entries = []
        for pkt in ctx.packets:
            ex = pkt.extra
            if not ex.get("http_method"):
                continue
            entries.append({
                "ts":     pkt.timestamp * 1000,
                "src":    pkt.src_ip,
                "dst":    pkt.dst_ip,
                "method": ex.get("http_method", ""),
                "host":   ex.get("http_host", ""),
                "uri":    ex.get("http_uri", ""),
                "ua":     ex.get("http_user_agent", "") or "(no User-Agent)",
                "bytes":  pkt.payload_len or pkt.orig_len or 0,
            })
        return entries

    def build_figure(self, entries: List[dict], params: dict):
        import plotly.graph_objects as go

        if not entries:
            fig = go.Figure()
            fig.update_layout(title="No HTTP request packets found in capture")
            return fig

        entries = sorted(entries, key=lambda e: e["ts"])

        seen_ips, seen_ip_set = [], set()
        for e in entries:
            if e["src"] not in seen_ip_set:
                seen_ips.append(e["src"])
                seen_ip_set.add(e["src"])

        ua_counts = defaultdict(int)
        for e in entries:
            ua_counts[e["ua"]] += 1
        ua_sorted = sorted(ua_counts, key=lambda u: -ua_counts[u])

        ua_color = {}
        for i, ua in enumerate(ua_sorted):
            ua_color[ua] = _DEFAULT_COLOR if ua == "(no User-Agent)" else _PALETTE[i % len(_PALETTE)]

        trace_map = defaultdict(lambda: {"x": [], "y": [], "text": [], "sizes": []})
        for e in entries:
            ua = e["ua"]
            sz = max(6, min(16, 6 + (e["bytes"] / 2000) * 10))
            trace_map[ua]["x"].append(e["ts"])
            trace_map[ua]["y"].append(e["src"])
            trace_map[ua]["sizes"].append(sz)
            trace_map[ua]["text"].append(
                f"<b>{e['method']} {_shorten(e['uri'], 80)}</b><br>"
                f"Host: {e['host'] or '—'}<br>"
                f"UA: {_shorten(e['ua'], 120)}<br>"
                f"Source: {e['src']}<br>"
                f"Dest: {e['dst']}<br>"
                f"Bytes: {e['bytes']:,}"
            )

        traces = []
        for ua in ua_sorted:
            if ua not in trace_map:
                continue
            d = trace_map[ua]
            traces.append(go.Scatter(
                mode="markers", name=_shorten(ua, 50),
                x=d["x"], y=d["y"],
                text=d["text"],
                hovertemplate="%{text}<extra></extra>",
                marker=dict(color=ua_color[ua], size=d["sizes"], opacity=0.85,
                            line=dict(width=0)),
            ))

        height = max(300, 80 + len(seen_ips) * 28)
        fig = go.Figure(data=traces)
        fig.update_layout(
            title=dict(
                text=f"HTTP User-Agent timeline · {len(entries)} requests · {len(seen_ips)} sources · {len(ua_sorted)} UAs",
                font=dict(color="#e6edf3", size=12),
            ),
            xaxis=dict(title=dict(text="Time", font=dict(color="#484f58")),
                       type="date", tickformat="%H:%M:%S"),
            yaxis=dict(title=dict(text="Source IP", font=dict(color="#484f58")),
                       type="category", categoryorder="array",
                       categoryarray=list(reversed(seen_ips)),
                       tickfont=dict(size=9, family="JetBrains Mono, monospace"),
                       automargin=True),
            height=height,
            margin=dict(l=160, r=20, t=50, b=60),
            legend=dict(bgcolor="rgba(14,17,23,0.8)", bordercolor="rgba(48,54,61,0.8)",
                        borderwidth=1, font=dict(size=9, family="JetBrains Mono, monospace"),
                        x=1.01, y=1, xanchor="left", yanchor="top"),
        )
        return fig
