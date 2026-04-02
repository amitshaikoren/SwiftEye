"""
TTL Over Time — Research Chart

Question answered:
    Did the TTL between two peers stay consistent over the session,
    or did it shift at some point?

Two scatter traces — one per direction (A→B and B→A).
X axis = time. Y axis = TTL value. Dot size = bytes.

Reference lines at canonical TTL origins (64, 128, 255) help
the researcher immediately see what OS/device class each direction
looks like.

No anomaly detection — just the raw values. The researcher decides
what's significant.
"""

from datetime import datetime, timezone
from research import ResearchChart, Param, AnalysisContext, SWIFTEYE_LAYOUT


class TTLOverTime(ResearchChart):
    name        = "ttl_over_time"
    title       = "TTL over time between two peers"
    description = "Raw TTL values for packets in both directions between two IPs — spot routing changes or inconsistencies"
    category    = "host"
    params = [
        Param(
            name="ip_a",
            label="IP A",
            type="ip",
            placeholder="e.g. 192.168.1.177",
        ),
        Param(
            name="ip_b",
            label="IP B",
            type="ip",
            placeholder="e.g. 44.217.73.9",
        ),
    ]

    def compute(self, ctx: AnalysisContext, params: dict) -> dict:
        ip_a = params["ip_a"].strip()
        ip_b = params["ip_b"].strip()

        pkts_atob = []
        pkts_btoa = []

        for pkt in ctx.packets:
            if pkt.src_ip == ip_a and pkt.dst_ip == ip_b and pkt.ttl:
                pkts_atob.append(pkt)
            elif pkt.src_ip == ip_b and pkt.dst_ip == ip_a and pkt.ttl:
                pkts_btoa.append(pkt)

        if not pkts_atob and not pkts_btoa:
            return {
                "data": [],
                "layout": {
                    **SWIFTEYE_LAYOUT,
                    "title": {"text": f"No packets found between {ip_a} and {ip_b}", "font": {"color": "#8b949e"}},
                },
            }

        def make_trace(pkts, label, color):
            if not pkts:
                return None
            sizes = [max(4, min(18, (p.orig_len ** 0.5) * 0.55)) for p in pkts]
            texts = [
                f"Direction: {label}<br>"
                f"TTL: {p.ttl}<br>"
                f"Bytes: {p.orig_len:,}<br>"
                f"Proto: {p.protocol or p.transport}<br>"
                f"Src port: {p.src_port} → Dst port: {p.dst_port}<br>"
                f"Time: {_fmt_time(p.timestamp)}"
                for p in pkts
            ]
            return {
                "type": "scatter",
                "mode": "markers",
                "name": label,
                "x": [p.timestamp * 1000 for p in pkts],
                "y": [p.ttl for p in pkts],
                "text": texts,
                "hovertemplate": "%{text}<extra></extra>",
                "marker": {
                    "color": color,
                    "size": sizes,
                    "opacity": 0.82,
                    "line": {"width": 0.5, "color": color},
                },
            }

        traces = []
        t_atob = make_trace(pkts_atob, f"{ip_a} → {ip_b}", "#58a6ff")
        t_btoa = make_trace(pkts_btoa, f"{ip_b} → {ip_a}", "#3fb950")
        if t_atob: traces.append(t_atob)
        if t_btoa: traces.append(t_btoa)

        # TTL reference lines at canonical values
        all_pkts = pkts_atob + pkts_btoa
        t_min = min(p.timestamp * 1000 for p in all_pkts) - 5000
        t_max = max(p.timestamp * 1000 for p in all_pkts) + 5000
        all_ttls = [p.ttl for p in all_pkts]
        ttl_min = max(0, min(all_ttls) - 10)
        ttl_max = min(255, max(all_ttls) + 10)

        for ref_val, ref_label in [(64, "64 — Linux/macOS origin"), (128, "128 — Windows origin"), (255, "255 — network device")]:
            if ttl_min <= ref_val <= ttl_max:
                traces.append({
                    "type": "scatter",
                    "mode": "lines",
                    "name": ref_label,
                    "x": [t_min, t_max],
                    "y": [ref_val, ref_val],
                    "line": {"color": "#30363d", "width": 1, "dash": "dot"},
                    "hoverinfo": "skip",
                    "showlegend": True,
                })

        layout = {
            **SWIFTEYE_LAYOUT,
            "title": {
                "text": f"TTL over time · {ip_a} ⇄ {ip_b}",
                "font": {"color": "#e6edf3", "size": 13},
            },
            "xaxis": {
                **SWIFTEYE_LAYOUT["xaxis"],
                "title": {"text": "Time", "font": {"color": "#484f58"}},
                "type": "date",
                "range": [t_min, t_max],
                "tickformat": "%H:%M:%S",
            },
            "yaxis": {
                **SWIFTEYE_LAYOUT["yaxis"],
                "title": {"text": "TTL", "font": {"color": "#484f58"}},
                "range": [ttl_min - 2, ttl_max + 2],
            },
            "height": 380,
        }

        return {"data": traces, "layout": layout}


def _fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]
