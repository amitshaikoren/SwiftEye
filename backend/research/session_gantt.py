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

from research import ResearchChart, Param, AnalysisContext, SWIFTEYE_LAYOUT, PROTOCOL_COLORS
from datetime import datetime, timezone
from collections import defaultdict


def _fmt(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")


class SessionGantt(ResearchChart):
    name        = "session_gantt"
    title       = "Session Gantt"
    description = "All sessions — when each started, ended, and how long it lasted. No input required."
    params = []   # no params — shows everything

    def compute(self, ctx: AnalysisContext, params: dict) -> dict:
        sessions = ctx.sessions

        if not sessions:
            return {
                "data": [],
                "layout": {
                    **SWIFTEYE_LAYOUT,
                    "title": {"text": "No sessions in capture", "font": {"color": "#8b949e"}},
                },
            }

        sessions = sorted(sessions, key=lambda s: s.get("start_time", 0))
        # Use the time window start as the x-axis origin so the chart always
        # shows time relative to the selected burst/window, not the full capture.
        # ctx.time_range is set by the server when _timeStart/_timeEnd are passed.
        if ctx.time_range and ctx.time_range[0] is not None:
            t_global_min = ctx.time_range[0]
        else:
            t_global_min = sessions[0].get("start_time", 0)

        def row_label(s):
            src = s.get("src_ip", "?")
            dst = s.get("dst_ip", "?")
            dport = s.get("dst_port", 0)
            return f"{src} → {dst}:{dport}"

        proto_data = defaultdict(lambda: {"base": [], "width": [], "y": [], "text": []})

        for s in sessions:
            proto = s.get("protocol") or s.get("transport") or "OTHER"
            t0 = s.get("start_time", 0)
            t1 = s.get("end_time") or t0
            duration = max(0.5, t1 - t0)

            tcp_state = []
            if s.get("has_handshake"): tcp_state.append("SYN✓")
            if s.get("has_fin"):       tcp_state.append("FIN✓")
            if s.get("has_reset"):     tcp_state.append("RST")
            state_str = " ".join(tcp_state) if tcp_state else "incomplete"

            hover = (
                f"{s.get('src_ip')} → {s.get('dst_ip')}:{s.get('dst_port')}<br>"
                f"Protocol: {proto}<br>"
                f"Start: {_fmt(t0)} (+{t0 - t_global_min:.1f}s)<br>"
                f"End: {_fmt(t1)} (+{t1 - t_global_min:.1f}s)<br>"
                f"Duration: {duration:.1f}s<br>"
                f"Packets: {s.get('packet_count', 0):,}<br>"
                f"Bytes: {s.get('total_bytes', 0):,}<br>"
                f"TCP: {state_str}"
            )

            proto_data[proto]["base"].append(round(t0 - t_global_min, 3))
            proto_data[proto]["width"].append(round(duration, 3))
            proto_data[proto]["y"].append(row_label(s))
            proto_data[proto]["text"].append(hover)

        traces = []
        for proto, d in sorted(proto_data.items()):
            color = PROTOCOL_COLORS.get(proto, PROTOCOL_COLORS["OTHER"])
            traces.append({
                "type": "bar",
                "name": proto,
                "orientation": "h",
                "base": d["base"],
                "x": d["width"],
                "y": d["y"],
                "text": d["text"],
                "hovertemplate": "%{text}<extra></extra>",
                "marker": {
                    "color": color,
                    "opacity": 0.8,
                    "line": {"width": 0.5, "color": color},
                },
            })

        t_max = max(
            (s.get("end_time") or s.get("start_time", 0)) - t_global_min
            for s in sessions
        ) or 1
        # When a time window is active, clamp the x-axis to the window duration
        # so bars from long-running sessions don't stretch the chart past the window.
        if ctx.time_range and ctx.time_range[1] is not None:
            t_max = min(t_max, ctx.time_range[1] - t_global_min)
        pad = t_max * 0.02

        n = len(sessions)
        row_h = max(10, min(24, 700 // max(n, 1)))
        height = min(900, max(350, 80 + n * (row_h + 3)))

        layout = {
            **SWIFTEYE_LAYOUT,
            "title": {
                "text": f"Session Gantt — {n} sessions",
                "font": {"color": "#e6edf3", "size": 13},
            },
            "barmode": "overlay",
            "xaxis": {
                **SWIFTEYE_LAYOUT["xaxis"],
                "title": {"text": "Seconds since window start" if ctx.time_range else "Seconds since capture start", "font": {"color": "#484f58"}},
                "range": [-pad, t_max + pad],
                "ticksuffix": "s",
            },
            "yaxis": {
                **SWIFTEYE_LAYOUT["yaxis"],
                "title": {"text": "", "font": {"color": "#484f58"}},
                "type": "category",
                "categoryorder": "array",
                "categoryarray": [row_label(s) for s in sessions],
                "tickfont": {"size": 9},
                "automargin": True,
            },
            "height": height,
            "margin": {"l": 180, "r": 20, "t": 50, "b": 60},
        }

        return {"data": traces, "layout": layout}
