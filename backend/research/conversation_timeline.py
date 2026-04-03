"""
Conversation Timeline — Research Chart

Question answered:
    Who talked to a target IP, when, and on what protocol/port?

Each peer of the target IP gets its own row on the Y axis.
Each packet is a dot on the X axis (time).
Dot colour = protocol. Dot size = bytes transferred.

Useful for:
    - Seeing which peers are persistent vs transient
    - Spotting sudden new peers appearing mid-capture
    - Identifying which protocol dominates each relationship
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import List

from research import ResearchChart, Param, AnalysisContext, SWIFTEYE_LAYOUT, PROTOCOL_COLORS


class ConversationTimeline(ResearchChart):
    name        = "conversation_timeline"
    title       = "Conversation timeline"
    description = "All peers of a target IP over time — who talked, when, on what protocol"
    category    = "host"
    params = [
        Param(
            name="target_ip",
            label="Target IP",
            type="ip",
            placeholder="e.g. 192.168.1.177",
        ),
    ]
    entry_schema = {
        'peer':      'ip',
        'protocol':  'list',
        'direction': {'type': 'list', 'options': ['in', 'out']},
        'bytes':     'numeric',
        'src_port':  'numeric',
        'dst_port':  'numeric',
    }

    def build_data(self, ctx: AnalysisContext, params: dict) -> List[dict]:
        target = params["target_ip"].strip()
        entries = []
        for pkt in ctx.packets:
            if pkt.src_ip != target and pkt.dst_ip != target:
                continue
            peer = pkt.dst_ip if pkt.src_ip == target else pkt.src_ip
            direction = "out" if pkt.src_ip == target else "in"
            proto = pkt.protocol or pkt.transport or "OTHER"
            entries.append({
                "ts":       pkt.timestamp * 1000,
                "peer":     peer,
                "protocol": proto,
                "direction": direction,
                "bytes":    pkt.orig_len,
                "src_port": pkt.src_port,
                "dst_port": pkt.dst_port,
            })
        return entries

    def build_figure(self, entries: List[dict], params: dict):
        target = params["target_ip"].strip()

        if not entries:
            import plotly.graph_objects as go
            fig = go.Figure()
            fig.update_layout(title=f"No packets found for {target}")
            return fig

        import plotly.graph_objects as go

        # Build Y-axis order: peers sorted by first-seen time
        peer_first = {}
        for e in entries:
            if e["peer"] not in peer_first:
                peer_first[e["peer"]] = e["ts"]
        peers = sorted(peer_first, key=peer_first.get)

        # One trace per protocol
        proto_traces = defaultdict(lambda: {"x": [], "y": [], "size": [], "text": []})
        for e in entries:
            proto = e["protocol"]
            size = max(4, min(20, (e["bytes"] ** 0.5) * 0.6))
            ts_str = _fmt_time(e["ts"] / 1000)
            proto_traces[proto]["x"].append(e["ts"])
            proto_traces[proto]["y"].append(e["peer"])
            proto_traces[proto]["size"].append(size)
            proto_traces[proto]["text"].append(
                f"Peer: {e['peer']}<br>"
                f"Proto: {proto}<br>"
                f"Direction: {e['direction']}<br>"
                f"Bytes: {e['bytes']:,}<br>"
                f"Src port: {e['src_port']}<br>"
                f"Dst port: {e['dst_port']}<br>"
                f"Time: {ts_str}"
            )

        traces = []
        for proto, d in sorted(proto_traces.items()):
            color = PROTOCOL_COLORS.get(proto, PROTOCOL_COLORS["OTHER"])
            traces.append(go.Scatter(
                mode="markers",
                name=proto,
                x=d["x"], y=d["y"],
                text=d["text"],
                hovertemplate="%{text}<extra></extra>",
                marker=dict(
                    color=color, size=d["size"],
                    opacity=0.8, line=dict(width=0.5, color=color),
                ),
            ))

        t_min = min(e["ts"] for e in entries)
        t_max = max(e["ts"] for e in entries)

        fig = go.Figure(data=traces)
        fig.update_layout(
            title=dict(text=f"Conversation timeline · {target}", font=dict(color="#e6edf3", size=13)),
            xaxis=dict(title=dict(text="Time", font=dict(color="#484f58")),
                       type="date", range=[t_min - 10000, t_max + 10000], tickformat="%H:%M:%S"),
            yaxis=dict(title=dict(text="Peer IP", font=dict(color="#484f58")),
                       type="category", categoryorder="array", categoryarray=peers),
            height=max(300, 60 + len(peers) * 38),
            margin=dict(l=130, r=20, t=50, b=60),
        )
        return fig


def _fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]
