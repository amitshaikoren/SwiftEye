"""
Process Gantt — Forensic Research Chart

Question answered:
    When did each process start, and how long was it active (judged by the
    span of events it generated)?

One horizontal bar per process_create event. Bar starts at process creation
time and extends to the timestamp of the last event sourced from that process
in the capture. Processes that appear only once (no downstream events) show
as a short 1-second stub.

Useful for:
    - Spotting long-lived suspicious processes
    - Understanding injection timing relative to parent
    - Correlating process lifetimes with network/file activity
"""

import os
from collections import defaultdict
from datetime import timezone
from typing import List

import plotly.graph_objects as go

from workspaces.forensic.research import ForensicResearchChart, ForensicContext, register_chart

_PROCESS_COLOR = "#4fc3f7"


def _ts_epoch(dt) -> float:
    """Convert datetime → UTC epoch float; return 0 on failure."""
    if dt is None:
        return 0.0
    try:
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc).timestamp()
        return dt.timestamp()
    except Exception:
        return 0.0


def _fmt(epoch: float) -> str:
    from datetime import datetime
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%H:%M:%S")


class ProcessGantt(ForensicResearchChart):
    name        = "process_gantt"
    title       = "Process Timeline"
    description = "When each process was created and how long it generated events."
    category    = "capture"
    params      = []

    def build_data(self, ctx: ForensicContext, params: dict) -> List[dict]:
        # Map guid → latest epoch seen across all events where this guid is source
        latest_by_guid: dict = defaultdict(float)
        for ev in ctx.events:
            guid = ev.src_entity.get("guid") or ""
            if not guid:
                continue
            epoch = _ts_epoch(ev.ts)
            if epoch and epoch > latest_by_guid[guid]:
                latest_by_guid[guid] = epoch

        entries = []
        seen_guids: set = set()
        for ev in ctx.events:
            if ev.action_type != "process_create":
                continue
            guid = ev.src_entity.get("guid") or ""
            if guid in seen_guids:
                continue
            seen_guids.add(guid)

            start = _ts_epoch(ev.ts)
            if not start:
                continue

            end = max(latest_by_guid.get(guid, start), start + 1.0)

            image = ev.src_entity.get("image") or ""
            label = os.path.basename(image) if image else guid[:16]
            pid   = ev.src_entity.get("pid")
            row   = f"{label} ({pid})" if pid else label
            user  = ev.src_entity.get("user") or ""

            entries.append({
                "row":      row,
                "label":    label,
                "start":    start,
                "end":      end,
                "duration": round(end - start, 3),
                "pid":      pid,
                "user":     user,
                "image":    image,
                "guid":     guid,
            })

        # Sort chronologically
        entries.sort(key=lambda e: e["start"])
        if not entries:
            return entries

        t0 = entries[0]["start"]
        for e in entries:
            e["start_rel"] = round(e["start"] - t0, 3)
            e["end_rel"]   = round(e["end"]   - t0, 3)
            e["start_fmt"] = _fmt(e["start"])
            e["end_fmt"]   = _fmt(e["end"])
            e["_t0"]       = t0
        return entries

    def build_figure(self, entries: List[dict], params: dict) -> go.Figure:
        if not entries:
            fig = go.Figure()
            fig.update_layout(title="No process_create events found")
            return fig

        t_max = max(e["end_rel"] for e in entries) or 1
        pad   = t_max * 0.02
        n     = len(entries)
        row_h = max(10, min(28, 700 // max(n, 1)))
        height = min(900, max(300, 80 + n * (row_h + 3)))

        hover_texts = []
        for e in entries:
            hover_texts.append(
                f"{e['label']}<br>"
                f"PID: {e['pid']}<br>"
                f"User: {e['user'] or '—'}<br>"
                f"Start: {e['start_fmt']} (+{e['start_rel']:.1f}s)<br>"
                f"Last event: {e['end_fmt']} (+{e['end_rel']:.1f}s)<br>"
                f"Active span: {e['duration']:.1f}s<br>"
                f"GUID: {e['guid'][:32] if e['guid'] else '—'}"
            )

        row_order = [e["row"] for e in entries]

        fig = go.Figure(go.Bar(
            name="processes",
            orientation="h",
            base=[e["start_rel"] for e in entries],
            x=[e["duration"] for e in entries],
            y=[e["row"] for e in entries],
            text=hover_texts,
            hovertemplate="%{text}<extra></extra>",
            marker=dict(
                color=_PROCESS_COLOR,
                opacity=0.75,
                line=dict(width=0.8, color=_PROCESS_COLOR),
            ),
        ))

        fig.update_layout(
            title=dict(text=f"Process Timeline — {n} processes", font=dict(color="#e6edf3", size=13)),
            xaxis=dict(
                title=dict(text="Seconds since first process", font=dict(color="#484f58")),
                range=[-pad, t_max + pad],
                ticksuffix="s",
            ),
            yaxis=dict(
                title=dict(text="", font=dict(color="#484f58")),
                type="category",
                categoryorder="array",
                categoryarray=row_order,
                tickfont=dict(size=9),
                automargin=True,
            ),
            height=height,
            margin=dict(l=180, r=20, t=50, b=60),
        )
        return fig


register_chart(ProcessGantt())
