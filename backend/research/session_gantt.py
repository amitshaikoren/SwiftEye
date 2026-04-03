"""
Session Gantt — Research Chart

Question answered:
    When did each session in the capture start and end, and how long did it last?

No input required — shows all sessions in the capture. One row per session,
horizontal bars from session start to end. Bar colour = protocol.
X axis = seconds since capture start (readable numbers, not Unix timestamps).
Hover shows full session detail.

Useful for:
    - Seeing the temporal shape of all capture activity at a glance
    - Spotting sessions that are abnormally long or short
    - Identifying beaconing (regular short sessions to the same peer)
    - Seeing which sessions overlapped in time
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import List

from research import ResearchChart, Param, AnalysisContext, SWIFTEYE_LAYOUT, PROTOCOL_COLORS


def _fmt(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")


MAX_ROWS = 2000


class SessionGantt(ResearchChart):
    name        = "session_gantt"
    title       = "Session Gantt"
    description = "All sessions — when each started, ended, and how long it lasted. No input required."
    category    = "session"
    params      = []

    def build_data(self, ctx: AnalysisContext, params: dict) -> List[dict]:
        sessions = ctx.sessions
        if not sessions:
            return []

        sessions = sorted(sessions, key=lambda s: s.get("start_time", 0))
        total = len(sessions)
        if total > MAX_ROWS:
            sessions = sorted(sessions, key=lambda s: s.get("packet_count", 0), reverse=True)[:MAX_ROWS]
            sessions = sorted(sessions, key=lambda s: s.get("start_time", 0))

        if ctx.time_range and ctx.time_range[0] is not None:
            t0_global = ctx.time_range[0]
        else:
            t0_global = sessions[0].get("start_time", 0)

        entries = []
        for s in sessions:
            proto = s.get("protocol") or s.get("transport") or "OTHER"
            t0    = s.get("start_time", 0)
            t1    = s.get("end_time") or t0
            dur   = max(0.5, t1 - t0)

            tcp_state = []
            if s.get("has_handshake"): tcp_state.append("SYN✓")
            if s.get("has_fin"):       tcp_state.append("FIN✓")
            if s.get("has_reset"):     tcp_state.append("RST")
            state_str = " ".join(tcp_state) if tcp_state else "incomplete"

            src_ip  = s.get("src_ip", "?")
            dst_ip  = s.get("dst_ip", "?")
            dst_port = s.get("dst_port", 0)
            row_label = f"{src_ip} → {dst_ip}:{dst_port}"

            entries.append({
                "ts":        t0 * 1000,      # start time — used as sort / time axis ref
                "start_rel": round(t0 - t0_global, 3),
                "duration":  round(dur, 3),
                "row":       row_label,
                "protocol":  proto,
                "src_ip":    src_ip,
                "dst_ip":    dst_ip,
                "dst_port":  dst_port,
                "packets":   s.get("packet_count", 0),
                "bytes":     s.get("total_bytes", 0),
                "tcp_state": state_str,
                "start_fmt": _fmt(t0),
                "end_fmt":   _fmt(t1),
                "end_rel":   round(t1 - t0_global, 3),
                # store for figure rebuild
                "_t0_global": t0_global,
                "_total":     total,
                "_truncated": total > MAX_ROWS,
            })
        return entries

    def build_figure(self, entries: List[dict], params: dict):
        import plotly.graph_objects as go

        if not entries:
            fig = go.Figure()
            fig.update_layout(title="No sessions in capture")
            return fig

        t0_global  = entries[0]["_t0_global"]
        total      = entries[0]["_total"]
        truncated  = entries[0]["_truncated"]

        proto_data = defaultdict(lambda: {"base": [], "width": [], "y": [], "text": []})
        for e in entries:
            proto = e["protocol"]
            hover = (
                f"{e['src_ip']} → {e['dst_ip']}:{e['dst_port']}<br>"
                f"Protocol: {proto}<br>"
                f"Start: {e['start_fmt']} (+{e['start_rel']:.1f}s)<br>"
                f"End: {e['end_fmt']} (+{e['end_rel']:.1f}s)<br>"
                f"Duration: {e['duration']:.1f}s<br>"
                f"Packets: {e['packets']:,}<br>"
                f"Bytes: {e['bytes']:,}<br>"
                f"TCP: {e['tcp_state']}"
            )
            proto_data[proto]["base"].append(e["start_rel"])
            proto_data[proto]["width"].append(e["duration"])
            proto_data[proto]["y"].append(e["row"])
            proto_data[proto]["text"].append(hover)

        traces = []
        for proto, d in sorted(proto_data.items()):
            color = PROTOCOL_COLORS.get(proto, PROTOCOL_COLORS["OTHER"])
            traces.append(go.Bar(
                name=proto, orientation="h",
                base=d["base"], x=d["width"], y=d["y"],
                text=d["text"],
                hovertemplate="%{text}<extra></extra>",
                marker=dict(color=color, opacity=0.8, line=dict(width=0.5, color=color)),
            ))

        t_max = max(e["end_rel"] for e in entries) or 1
        if ctx_range := entries[0].get("_t0_global"):
            pass  # already in start_rel / end_rel

        n = len(entries)
        row_h  = max(10, min(24, 700 // max(n, 1)))
        height = min(900, max(350, 80 + n * (row_h + 3)))
        pad    = t_max * 0.02

        title_text = f"Session Gantt — {n} sessions"
        if truncated:
            title_text = f"Session Gantt — top {n} of {total:,} sessions (by packet count)"

        row_order = [e["row"] for e in entries]

        fig = go.Figure(data=traces)
        fig.update_layout(
            title=dict(text=title_text, font=dict(color="#e6edf3", size=13)),
            barmode="overlay",
            xaxis=dict(title=dict(text="Seconds since window start", font=dict(color="#484f58")),
                       range=[-pad, t_max + pad], ticksuffix="s"),
            yaxis=dict(title=dict(text="", font=dict(color="#484f58")),
                       type="category", categoryorder="array", categoryarray=row_order,
                       tickfont=dict(size=9), automargin=True),
            height=height,
            margin=dict(l=180, r=20, t=50, b=60),
        )
        return fig
