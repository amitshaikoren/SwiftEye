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

    def compute(self, ctx: AnalysisContext, params: dict) -> dict:
        target = params["target_ip"].strip()

        # collect packets involving target
        relevant = [
            p for p in ctx.packets
            if p.src_ip == target or p.dst_ip == target
        ]

        if not relevant:
            return {
                "data": [],
                "layout": {
                    **SWIFTEYE_LAYOUT,
                    "title": {"text": f"No packets found for {target}", "font": {"color": "#8b949e"}},
                },
            }

        # group by peer
        peer_packets = defaultdict(list)
        for pkt in relevant:
            peer = pkt.dst_ip if pkt.src_ip == target else pkt.src_ip
            peer_packets[peer].append(pkt)

        # sort peers by first-seen time for stable Y ordering
        peers = sorted(peer_packets.keys(), key=lambda p: peer_packets[p][0].timestamp)

        # build one trace per protocol (so legend works cleanly)
        proto_traces = defaultdict(lambda: {"x": [], "y": [], "size": [], "text": [], "peer": []})

        for peer in peers:
            for pkt in peer_packets[peer]:
                proto = pkt.protocol or pkt.transport or "OTHER"
                t_str = _fmt_time(pkt.timestamp)
                direction = "out" if pkt.src_ip == target else "in"
                proto_traces[proto]["x"].append(pkt.timestamp * 1000)
                proto_traces[proto]["y"].append(peer)
                # size: sqrt scale so large packets don't dominate visually
                size = max(4, min(20, (pkt.orig_len ** 0.5) * 0.6))
                proto_traces[proto]["size"].append(size)
                proto_traces[proto]["text"].append(
                    f"Peer: {peer}<br>"
                    f"Proto: {proto}<br>"
                    f"Direction: {direction}<br>"
                    f"Bytes: {pkt.orig_len:,}<br>"
                    f"Src port: {pkt.src_port}<br>"
                    f"Dst port: {pkt.dst_port}<br>"
                    f"Time: {t_str}"
                )

        traces = []
        for proto, d in sorted(proto_traces.items()):
            color = PROTOCOL_COLORS.get(proto, PROTOCOL_COLORS["OTHER"])
            traces.append({
                "type": "scatter",
                "mode": "markers",
                "name": proto,
                "x": d["x"],
                "y": d["y"],
                "text": d["text"],
                "hovertemplate": "%{text}<extra></extra>",
                "marker": {
                    "color": color,
                    "size": d["size"],
                    "opacity": 0.8,
                    "line": {"width": 0.5, "color": color},
                },
            })

        t_min = min(p.timestamp * 1000 for p in relevant)
        t_max = max(p.timestamp * 1000 for p in relevant)

        layout = {
            **SWIFTEYE_LAYOUT,
            "title": {
                "text": f"Conversation timeline · {target}",
                "font": {"color": "#e6edf3", "size": 13},
            },
            "xaxis": {
                **SWIFTEYE_LAYOUT["xaxis"],
                "title": {"text": "Time", "font": {"color": "#484f58"}},
                "type": "date",
                "range": [t_min - 10000, t_max + 10000],
                "tickformat": "%H:%M:%S",
            },
            "yaxis": {
                **SWIFTEYE_LAYOUT["yaxis"],
                "title": {"text": "Peer IP", "font": {"color": "#484f58"}},
                "type": "category",
                "categoryorder": "array",
                "categoryarray": peers,
            },
            "height": max(300, 60 + len(peers) * 38),
            "margin": {"l": 130, "r": 20, "t": 50, "b": 60},
        }

        return {"data": traces, "layout": layout}


def _fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]
