"""
Research Chart Template — copy this file to create a new chart.

Steps:
  1. Copy this file to backend/research/my_chart_name.py
  2. Fill in the class attributes below
  3. Implement compute()
  4. Register in backend/server.py → _register_charts():
       ("research.my_chart_name", "MyChartClass")

This file is NOT registered and will never appear in the UI.
"""

import plotly.graph_objects as go

from research import ResearchChart, Param, AnalysisContext


class MyChart(ResearchChart):
    # ── Identity ──────────────────────────────────────────────────────────────
    name        = "my_chart"           # URL slug: /api/research/my_chart — must be unique
    title       = "My chart title"     # shown in the palette
    description = "One sentence: what question does this answer?"

    # ── Category ──────────────────────────────────────────────────────────────
    # Controls which palette section this chart appears under.
    # Pick one:  "host" | "session" | "capture" | "alerts" | "other"
    #
    #   host    — scoped to a specific IP (chart has an IP param)
    #   session — scoped to a single session (chart has a session_id param)
    #   capture — capture-wide view, no IP/session scoping
    #   alerts  — anomaly detection or scoring output
    #   other   — anything that doesn't fit above
    category    = "capture"

    # ── Params ────────────────────────────────────────────────────────────────
    # Declared params become input fields in the chart runner UI.
    # Remove params = [] if the chart needs no user input.
    params = [
        Param(
            name        = "target_ip",
            label       = "Target IP",
            type        = "ip",          # "text" | "ip" | "integer" | "float"
            required    = True,
            default     = "",
            placeholder = "e.g. 192.168.1.1",
        ),
        # Param(
        #     name        = "limit",
        #     label       = "Max points",
        #     type        = "integer",
        #     required    = False,
        #     default     = "500",
        # ),
    ]

    # ── compute() ─────────────────────────────────────────────────────────────
    def compute(self, ctx: AnalysisContext, params: dict) -> go.Figure:
        """
        Build and return a Plotly figure for this chart.

        The framework:
          - Filters ctx.packets and ctx.sessions to the user's time/protocol scope
            before calling compute() — you get pre-filtered data, not the full capture.
          - Applies SWIFTEYE_LAYOUT (dark theme, fonts, grid) after compute() returns.
          - Calls .to_dict() and sends the result to the frontend.

        So: just build the figure and return it. No .to_dict(), no SWIFTEYE_LAYOUT.

        ctx fields:
          ctx.packets     — list[PacketRecord]  (pre-filtered)
          ctx.sessions    — list[dict]           (pre-filtered)
          ctx.time_range  — (start_ts, end_ts) | None

        PacketRecord key fields:
          .src_ip, .dst_ip, .src_port, .dst_port
          .protocol, .transport
          .timestamp       (float, Unix seconds)
          .orig_len        (int, bytes on wire)
          .payload_len     (int, bytes payload)
          .ttl             (int)
          .tcp_flags_str   (str, e.g. "SYN ACK")
          .seq_num, .ack_num, .window_size
          .extra           (dict — dissector-specific fields, e.g. extra["dns_query"])

        params: dict keyed by Param.name → str (always a string; cast as needed)
        """
        ip = params["target_ip"]

        packets = [
            p for p in ctx.packets
            if p.src_ip == ip or p.dst_ip == ip
        ]

        if not packets:
            fig = go.Figure()
            fig.update_layout(title=f"No packets found for {ip}")
            return fig

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=[p.timestamp for p in packets],
            y=[p.orig_len  for p in packets],
            mode="markers",
            name="packet size",
            hovertext=[f"{p.src_ip} → {p.dst_ip}  {p.protocol}" for p in packets],
            hoverinfo="text+x+y",
        ))
        fig.update_layout(
            title=f"Packet sizes — {ip}",
            xaxis_title="Time",
            yaxis_title="Bytes",
        )
        return fig
