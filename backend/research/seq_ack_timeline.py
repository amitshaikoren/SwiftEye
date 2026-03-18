"""
Seq/Ack Timeline — Research Chart

Question answered:
    How did TCP sequence and acknowledgement numbers evolve over this session?
    Who was sending data, and are there retransmissions or stalls visible?

Chart type:
    Two-trace line+marker plot. X = time (seconds from session start).
    Y = relative SEQ number (bytes sent from session start, per direction).
    Colour = direction: initiator (green) vs responder (blue).

Why relative SEQ vs time (not raw SEQ vs ACK):
    Raw TCP sequence numbers start at a random 32-bit value, so plotting them raw
    produces a chart where all points cluster near e.g. 2,400,000,000 with no visible
    shape. Normalizing to (seq - isn) shows actual bytes-sent-over-time, which makes
    retransmits (flat or backward steps), stalls (horizontal plateau), and throughput
    (slope) immediately visible.

Params:
    session_id (required) — the session ID to analyse
"""

from research import ResearchChart, Param, AnalysisContext


class SeqAckTimelineChart(ResearchChart):
    name        = "seq_ack_timeline"
    title       = "Seq/Ack Timeline"
    description = "SEQ progress over time per direction — flat lines = stall, backward step = retransmit, slope = throughput."

    params = [
        Param(
            name        = "session_id",
            label       = "Session ID",
            type        = "text",
            required    = True,
            placeholder = "Paste a session ID from Session Detail",
        ),
        Param(
            name        = "mode",
            label       = "Chart mode",
            type        = "text",
            required    = False,
            default     = "time",
            placeholder = "time | seqack",
        ),
    ]

    def compute(self, ctx: AnalysisContext, params: dict) -> dict:
        session_id = params.get("session_id", "").strip()
        mode = params.get("mode", "time").strip().lower()  # "time" or "seqack"
        if not session_id:
            return {"data": [], "layout": {"title": "No session ID provided"}}

        session = next((s for s in ctx.sessions if s["id"] == session_id), None)
        if not session:
            return {"data": [], "layout": {"title": f"Session not found: {session_id[:24]}…"}}

        initiator_ip = session.get("initiator_ip", "")

        # For bytes/time mode: collect timestamp + bytes for ANY protocol
        # For seqack mode: collect TCP seq/ack only
        if mode == "time":
            init_time_pts = []  # (timestamp, cumulative_bytes)
            resp_time_pts = []
            for pkt in ctx.packets:
                if pkt.session_key != session_id:
                    continue
                entry = (pkt.timestamp, pkt.orig_len)
                if pkt.src_ip == initiator_ip:
                    init_time_pts.append(entry)
                else:
                    resp_time_pts.append(entry)

            if not init_time_pts and not resp_time_pts:
                return {
                    "data": [],
                    "layout": {
                        "paper_bgcolor": "rgba(0,0,0,0)",
                        "plot_bgcolor":  "rgba(0,0,0,0)",
                        "annotations": [{
                            "text": "No packet data for this session",
                            "xref": "paper", "yref": "paper", "x": 0.5, "y": 0.5,
                            "showarrow": False, "font": {"color": "#8b949e", "size": 12},
                        }],
                    }
                }

            init_time_pts.sort(key=lambda p: p[0])
            resp_time_pts.sort(key=lambda p: p[0])

            src_label = f"{session.get('initiator_ip','?')}:{session.get('initiator_port','?')}"
            dst_label = f"{session.get('responder_ip','?')}:{session.get('responder_port','?')}"
            protocol  = session.get("protocol", "")

            # Build cumulative bytes traces
            t0 = min(
                (init_time_pts[0][0] if init_time_pts else float('inf')),
                (resp_time_pts[0][0] if resp_time_pts else float('inf'))
            )
            traces = []
            for pts, label, color in [
                (init_time_pts, f"Initiator ({src_label})", "#3fb950"),
                (resp_time_pts, f"Responder ({dst_label})", "#58a6ff"),
            ]:
                if not pts:
                    continue
                xs, ys = [], []
                cum = 0
                for ts, size in pts:
                    cum += size
                    xs.append(round(ts - t0, 6))
                    ys.append(cum)
                traces.append({
                    "type": "scatter", "mode": "lines+markers",
                    "name": label,
                    "x": xs, "y": ys,
                    "line":   {"color": color, "width": 1.5},
                    "marker": {"color": color, "size": 4, "opacity": 0.7, "line": {"width": 0}},
                    "hovertemplate": "t+%{x:.3f}s  %{y:,} bytes<extra>" + label.split("(")[0].strip() + "</extra>",
                })

            xaxis_title = "Time (seconds from session start)"
            yaxis_title = "Cumulative bytes"
            chart_title = f"Bytes/Time — {protocol}  {src_label}"

        else:
            # SEQ/ACK mode — TCP only
            init_pts = []
            resp_pts = []

            for pkt in ctx.packets:
                if pkt.session_key != session_id:
                    continue
                if pkt.seq_num <= 0:
                    continue
                entry = (pkt.timestamp, pkt.seq_num, pkt.ack_num)
                if pkt.src_ip == initiator_ip:
                    init_pts.append(entry)
                else:
                    resp_pts.append(entry)

            if not init_pts and not resp_pts:
                return {
                    "data": [],
                    "layout": {
                        "paper_bgcolor": "rgba(0,0,0,0)",
                        "plot_bgcolor":  "rgba(0,0,0,0)",
                        "annotations": [{
                            "text": "No TCP sequence data (may be UDP or incomplete capture)",
                            "xref": "paper", "yref": "paper", "x": 0.5, "y": 0.5,
                            "showarrow": False, "font": {"color": "#8b949e", "size": 12},
                        }],
                    }
                }

            init_pts.sort(key=lambda p: p[0])
            resp_pts.sort(key=lambda p: p[0])

            src_label = f"{session.get('initiator_ip','?')}:{session.get('initiator_port','?')}"
            dst_label = f"{session.get('responder_ip','?')}:{session.get('responder_port','?')}"
            protocol  = session.get("protocol", "TCP")

            # SEQ vs ACK — normalize both axes to remove ISN offset
            def isn(pts, idx): return min(p[idx] for p in pts) if pts else 0
            init_seq_isn = isn(init_pts, 1);  init_ack_isn = isn(init_pts, 2) if any(p[2] > 0 for p in init_pts) else 0
            resp_seq_isn = isn(resp_pts, 1);  resp_ack_isn = isn(resp_pts, 2) if any(p[2] > 0 for p in resp_pts) else 0

            traces = []
            if init_pts:
                xs = [p[2] - init_ack_isn for p in init_pts if p[2] > 0]
                ys = [p[1] - init_seq_isn for p in init_pts if p[2] > 0]
                if xs:
                    traces.append({
                        "type": "scatter", "mode": "markers",
                        "name": f"Initiator ({src_label})",
                        "x": xs, "y": ys,
                        "marker": {"color": "#3fb950", "size": 5, "opacity": 0.8, "line": {"width": 0}},
                        "hovertemplate": "ACK+%{x:,}  SEQ+%{y:,}<extra>Initiator</extra>",
                    })
            if resp_pts:
                xs = [p[2] - resp_ack_isn for p in resp_pts if p[2] > 0]
                ys = [p[1] - resp_seq_isn for p in resp_pts if p[2] > 0]
                if xs:
                    traces.append({
                        "type": "scatter", "mode": "markers",
                        "name": f"Responder ({dst_label})",
                        "x": xs, "y": ys,
                        "marker": {"color": "#58a6ff", "size": 5, "opacity": 0.8, "line": {"width": 0}},
                        "hovertemplate": "ACK+%{x:,}  SEQ+%{y:,}<extra>Responder</extra>",
                    })
            xaxis_title = "ACK (bytes relative to ISN)"
            yaxis_title = "SEQ (bytes relative to ISN)"
            chart_title = f"SEQ vs ACK — {protocol}  {src_label}"

        layout = {
            "paper_bgcolor": "rgba(0,0,0,0)",
            "plot_bgcolor":  "rgba(14,17,23,0.4)",
            "font":          {"color": "#8b949e", "family": "JetBrains Mono, monospace", "size": 10},
            "margin":        {"l": 60, "r": 10, "t": 30, "b": 60},
            "title": {
                "text": chart_title,
                "font": {"size": 11, "color": "#e6edf3"},
                "x": 0, "xanchor": "left",
            },
            "xaxis": {
                "title":         {"text": xaxis_title, "font": {"size": 9}},
                "gridcolor":     "rgba(128,128,128,0.08)",
                "zerolinecolor": "rgba(128,128,128,0.15)",
                "tickfont":      {"size": 9},
                **({"ticksuffix": "s"} if mode != "seqack" else {"tickformat": ",d"}),
            },
            "yaxis": {
                "title":         {"text": yaxis_title, "font": {"size": 9}},
                "gridcolor":     "rgba(128,128,128,0.08)",
                "zerolinecolor": "rgba(128,128,128,0.15)",
                "tickformat":    "~s",
                "tickfont":      {"size": 9},
            },
            "legend": {
                "bgcolor":     "rgba(14,17,23,0.7)",
                "bordercolor": "rgba(48,54,61,0.8)",
                "borderwidth": 1,
                "font":        {"size": 9},
                "orientation": "h",
                "x": 0, "y": -0.2,
                "xanchor": "left", "yanchor": "top",
            },
            "hoverlabel": {
                "bgcolor": "#161b22",
                "font":    {"family": "JetBrains Mono, monospace", "size": 10},
            },
        }

        return {"data": traces, "layout": layout}


def register(registry):
    registry.register(SeqAckTimelineChart())
