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
from typing import List

from research import ResearchChart, Param, AnalysisContext, SWIFTEYE_LAYOUT


class TTLOverTime(ResearchChart):
    name        = "ttl_over_time"
    title       = "TTL over time between two peers"
    description = "Raw TTL values for packets in both directions between two IPs — spot routing changes or inconsistencies"
    category    = "host"
    params = [
        Param(name="ip_a", label="IP A", type="ip", placeholder="e.g. 192.168.1.177"),
        Param(name="ip_b", label="IP B", type="ip", placeholder="e.g. 44.217.73.9"),
    ]
    entry_schema = {
        'ttl':       'numeric',
        'direction': 'list',    # options collected at runtime: "A → B" / "B → A"
        'bytes':     'numeric',
        'protocol':  'list',
        'src_port':  'numeric',
        'dst_port':  'numeric',
    }

    def build_data(self, ctx: AnalysisContext, params: dict) -> List[dict]:
        ip_a = params["ip_a"].strip()
        ip_b = params["ip_b"].strip()
        entries = []
        for pkt in ctx.packets:
            if not pkt.ttl:
                continue
            if pkt.src_ip == ip_a and pkt.dst_ip == ip_b:
                direction = f"{ip_a} → {ip_b}"
            elif pkt.src_ip == ip_b and pkt.dst_ip == ip_a:
                direction = f"{ip_b} → {ip_a}"
            else:
                continue
            proto = pkt.protocol or pkt.transport or "OTHER"
            entries.append({
                "ts":        pkt.timestamp * 1000,
                "ttl":       pkt.ttl,
                "direction": direction,
                "bytes":     pkt.orig_len,
                "protocol":  proto,
                "src_port":  pkt.src_port,
                "dst_port":  pkt.dst_port,
            })
        return entries

    def build_figure(self, entries: List[dict], params: dict):
        ip_a = params["ip_a"].strip()
        ip_b = params["ip_b"].strip()

        import plotly.graph_objects as go

        if not entries:
            fig = go.Figure()
            fig.update_layout(title=f"No packets found between {ip_a} and {ip_b}")
            return fig

        dir_a = f"{ip_a} → {ip_b}"
        dir_b = f"{ip_b} → {ip_a}"
        colors = {dir_a: "#58a6ff", dir_b: "#3fb950"}

        from collections import defaultdict
        traces_data = defaultdict(lambda: {"x": [], "y": [], "size": [], "text": []})

        for e in entries:
            d = e["direction"]
            size = max(4, min(18, (e["bytes"] ** 0.5) * 0.55))
            ts_str = _fmt_time(e["ts"] / 1000)
            traces_data[d]["x"].append(e["ts"])
            traces_data[d]["y"].append(e["ttl"])
            traces_data[d]["size"].append(size)
            traces_data[d]["text"].append(
                f"Direction: {d}<br>"
                f"TTL: {e['ttl']}<br>"
                f"Bytes: {e['bytes']:,}<br>"
                f"Proto: {e['protocol']}<br>"
                f"Src port: {e['src_port']} → Dst port: {e['dst_port']}<br>"
                f"Time: {ts_str}"
            )

        traces = []
        for d, td in traces_data.items():
            color = colors.get(d, "#8b949e")
            traces.append(go.Scatter(
                mode="markers", name=d,
                x=td["x"], y=td["y"],
                text=td["text"],
                hovertemplate="%{text}<extra></extra>",
                marker=dict(color=color, size=td["size"], opacity=0.82,
                            line=dict(width=0.5, color=color)),
            ))

        all_ttls = [e["ttl"] for e in entries]
        t_min = min(e["ts"] for e in entries) - 5000
        t_max = max(e["ts"] for e in entries) + 5000
        ttl_min = max(0, min(all_ttls) - 10)
        ttl_max = min(255, max(all_ttls) + 10)

        for ref_val, ref_label in [
            (64,  "64 — Linux/macOS origin"),
            (128, "128 — Windows origin"),
            (255, "255 — network device"),
        ]:
            if ttl_min <= ref_val <= ttl_max:
                traces.append(go.Scatter(
                    mode="lines", name=ref_label,
                    x=[t_min, t_max], y=[ref_val, ref_val],
                    line=dict(color="#30363d", width=1, dash="dot"),
                    hoverinfo="skip", showlegend=True,
                ))

        fig = go.Figure(data=traces)
        fig.update_layout(
            title=dict(text=f"TTL over time · {ip_a} ⇄ {ip_b}", font=dict(color="#e6edf3", size=13)),
            xaxis=dict(title=dict(text="Time", font=dict(color="#484f58")),
                       type="date", range=[t_min, t_max], tickformat="%H:%M:%S"),
            yaxis=dict(title=dict(text="TTL", font=dict(color="#484f58")),
                       range=[ttl_min - 2, ttl_max + 2]),
            height=380,
        )
        return fig


def _fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]
