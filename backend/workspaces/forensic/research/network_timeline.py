"""
Network Connection Timeline — Forensic Research Chart

Question answered:
    Which external endpoints did each process connect to, and when?

One scatter point per network_connect event (EID 3). X = event time,
Y = destination ip:port. Color = source process. Hover shows full details.

Useful for:
    - Identifying C2 beaconing (regular connections to same endpoint)
    - Mapping which processes are calling out
    - Spotting unusual outbound ports (DNS, RDP, raw sockets)
"""

import os
from collections import defaultdict
from datetime import timezone
from typing import List

import plotly.graph_objects as go

from workspaces.forensic.research import ForensicResearchChart, ForensicContext, register_chart

_PROC_PALETTE = [
    "#58a6ff", "#3fb950", "#f0883e", "#d29922", "#bc8cff",
    "#f85149", "#4fc3f7", "#79c0ff", "#56d364", "#ffa657",
]


def _ts_epoch(dt) -> float:
    if dt is None:
        return 0.0
    try:
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc).timestamp()
        return dt.timestamp()
    except Exception:
        return 0.0


class NetworkTimeline(ForensicResearchChart):
    name        = "network_timeline"
    title       = "Network Connection Timeline"
    description = "Outbound connections per process over time — spot beaconing and C2 patterns."
    category    = "capture"
    params      = []

    def build_data(self, ctx: ForensicContext, params: dict) -> List[dict]:
        entries = []
        for ev in ctx.events:
            if ev.action_type != "network_connect":
                continue
            epoch = _ts_epoch(ev.ts)
            if not epoch:
                continue

            dst_ip   = ev.dst_entity.get("ip") or ev.dst_entity.get("hostname") or "?"
            dst_port = ev.dst_entity.get("port")
            dst_host = ev.dst_entity.get("hostname") or ""
            endpoint = f"{dst_ip}:{dst_port}" if dst_port else dst_ip

            image = ev.src_entity.get("image") or ""
            proc  = os.path.basename(image) if image else "unknown"
            pid   = ev.src_entity.get("pid")
            proc_label = f"{proc} ({pid})" if pid else proc

            protocol  = ev.fields.get("protocol") or ""
            initiated = ev.fields.get("initiated")

            entries.append({
                "ts":        epoch * 1000,
                "epoch":     epoch,
                "endpoint":  endpoint,
                "dst_ip":    dst_ip,
                "dst_port":  dst_port,
                "dst_host":  dst_host,
                "protocol":  protocol,
                "initiated": initiated,
                "process":   proc_label,
                "image":     image,
            })

        entries.sort(key=lambda e: e["epoch"])
        if not entries:
            return entries

        t0 = entries[0]["epoch"]
        for e in entries:
            e["rel"] = round(e["epoch"] - t0, 3)
        return entries

    def build_figure(self, entries: List[dict], params: dict) -> go.Figure:
        if not entries:
            fig = go.Figure()
            fig.update_layout(title="No network_connect events found")
            return fig

        by_proc: dict = defaultdict(list)
        for e in entries:
            by_proc[e["process"]].append(e)

        proc_color = {p: _PROC_PALETTE[i % len(_PROC_PALETTE)] for i, p in enumerate(sorted(by_proc))}

        traces = []
        for proc, evts in sorted(by_proc.items()):
            color = proc_color[proc]
            hover = [
                f"<b>{e['endpoint']}</b><br>"
                + (f"Hostname: {e['dst_host']}<br>" if e["dst_host"] and e["dst_host"] != e["dst_ip"] else "")
                + f"Protocol: {e['protocol'] or '—'}<br>"
                + f"Process: {e['process']}<br>"
                + f"Time: +{e['rel']:.1f}s"
                for e in evts
            ]
            traces.append(go.Scatter(
                name=proc,
                x=[e["rel"] for e in evts],
                y=[e["endpoint"] for e in evts],
                mode="markers",
                marker=dict(color=color, size=10, opacity=0.85,
                            line=dict(width=1, color=color + "88")),
                text=hover,
                hovertemplate="%{text}<extra></extra>",
            ))

        n = len(entries)
        unique_ep = len({e["endpoint"] for e in entries})
        t_max = max(e["rel"] for e in entries) or 1
        pad   = t_max * 0.04
        height = min(900, max(300, 80 + unique_ep * 30))

        fig = go.Figure(data=traces)
        fig.update_layout(
            title=dict(text=f"Network Connections — {n} events, {unique_ep} endpoints",
                       font=dict(color="#e6edf3", size=13)),
            xaxis=dict(
                title=dict(text="Seconds since first event", font=dict(color="#484f58")),
                range=[-pad, t_max + pad],
                ticksuffix="s",
            ),
            yaxis=dict(
                title=dict(text="", font=dict(color="#484f58")),
                tickfont=dict(size=9),
                automargin=True,
            ),
            legend=dict(font=dict(size=10)),
            height=height,
            margin=dict(l=180, r=20, t=50, b=60),
        )
        return fig


register_chart(NetworkTimeline())
