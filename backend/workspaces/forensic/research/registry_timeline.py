"""
Registry Write Timeline — Forensic Research Chart

Question answered:
    Which registry keys were written, by which processes, and when?

One scatter point per registry_set event (EID 13). X = event time,
Y = registry key path (last two path components for readability).
Color = source process image name. Hover shows full key + value written.

Useful for:
    - Spotting persistence mechanisms (Run keys, services, scheduled tasks)
    - Correlating registry activity with process creation events
    - Finding credential storage or configuration tampering
"""

import os
from datetime import timezone
from typing import List

import plotly.graph_objects as go

from workspaces.forensic.research import ForensicResearchChart, ForensicContext, register_chart

# Colorblind-friendly process palette (cycles)
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


def _hex_rgba(hex_color: str, alpha: float = 0.5) -> str:
    """Convert #rrggbb to rgba() — Plotly doesn't accept 8-digit hex."""
    h = hex_color.lstrip('#')
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f'rgba({r},{g},{b},{alpha})'


def _short_key(key: str) -> str:
    """Last two components of a registry path, prepended with hive."""
    parts = key.replace("/", "\\").split("\\")
    if len(parts) <= 3:
        return key
    return f"{parts[0]}\\…\\{parts[-2]}\\{parts[-1]}"


class RegistryTimeline(ForensicResearchChart):
    name        = "registry_timeline"
    title       = "Registry Write Timeline"
    description = "Registry keys written over time, coloured by source process."
    category    = "capture"
    params      = []

    def build_data(self, ctx: ForensicContext, params: dict) -> List[dict]:
        entries = []
        for ev in ctx.events:
            if ev.action_type != "registry_set":
                continue
            epoch = _ts_epoch(ev.ts)
            if not epoch:
                continue

            key      = ev.dst_entity.get("key") or ev.fields.get("target_object") or ""
            details  = ev.fields.get("details") or ""
            image    = ev.src_entity.get("image") or ""
            proc     = os.path.basename(image) if image else "unknown"
            pid      = ev.src_entity.get("pid")
            proc_label = f"{proc} ({pid})" if pid else proc

            entries.append({
                "ts":          epoch * 1000,
                "epoch":       epoch,
                "key":         key,
                "key_short":   _short_key(key) if key else "—",
                "details":     details[:120] if details else "",
                "process":     proc_label,
                "image":       image,
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
            fig.update_layout(title="No registry_set events found")
            return fig

        # Group by process for legend / color
        from collections import defaultdict
        by_proc: dict = defaultdict(list)
        for e in entries:
            by_proc[e["process"]].append(e)

        proc_color = {p: _PROC_PALETTE[i % len(_PROC_PALETTE)] for i, p in enumerate(sorted(by_proc))}

        traces = []
        for proc, evts in sorted(by_proc.items()):
            color = proc_color[proc]
            hover = [
                f"<b>{e['key_short']}</b><br>"
                f"Full key: {e['key']}<br>"
                f"Value: {e['details'] or '—'}<br>"
                f"Process: {e['process']}<br>"
                f"Time: +{e['rel']:.1f}s"
                for e in evts
            ]
            traces.append(go.Scatter(
                name=proc,
                x=[e["rel"] for e in evts],
                y=[e["key_short"] for e in evts],
                mode="markers",
                marker=dict(color=color, size=10, opacity=0.85,
                            line=dict(width=1, color=_hex_rgba(color, 0.5))),
                text=hover,
                hovertemplate="%{text}<extra></extra>",
            ))

        n = len(entries)
        unique_keys = len({e["key_short"] for e in entries})
        t_max = max(e["rel"] for e in entries) or 1
        pad   = t_max * 0.04
        height = min(900, max(300, 80 + unique_keys * 30))

        fig = go.Figure(data=traces)
        fig.update_layout(
            title=dict(text=f"Registry Writes — {n} events, {unique_keys} unique keys",
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
            margin=dict(l=220, r=20, t=50, b=60),
        )
        return fig


