"""
Research Chart Template — copy this file to create a new chart.

Steps:
  1. Copy this file to backend/research/my_chart_name.py
  2. Fill in the class attributes below
  3. Implement build_data() and build_figure()
  4. Register in backend/server.py → _register_charts():
       ("workspaces.network.research.my_chart_name", "MyChartClass")

This file is NOT registered and will never appear in the UI.

== Authoring pattern ==

Declare entry_schema, then split your logic into two methods:

  entry_schema = {
      'peer':      'ip',
      'protocol':  'list',                              # options collected at runtime
      'direction': {'type': 'list', 'options': ['in', 'out']},  # static options
      'bytes':     'numeric',
      'uri':       'string',
  }

  build_data(ctx, params)  → List[dict]
      Collect the raw records you want to plot. Return one flat dict per
      plotted point or bar. Keys must match entry_schema.
      Reserve "ts" for the time axis (excluded from filters by convention).

  build_figure(entries, params)  → go.Figure
      Receives the already-filtered entries list. Build and return a
      go.Figure. The framework applies SWIFTEYE_LAYOUT and calls .to_dict()
      — don't do either yourself.

This mirrors the typical Jupyter workflow:

  # Cell 1: build data
  entries = [{"ts": pkt.timestamp * 1000, "peer": peer, ...}
             for pkt in packets if ...]

  # Cell 2: plot
  fig = px.scatter(pd.DataFrame(entries), x="ts", y="peer", color="protocol")

== entry_schema field types ==

  'ip'      — IPv4 address; frontend renders a text input (prefix/exact match)
  'string'  — free text; frontend renders a contains text input
  'numeric' — int or float; frontend renders min/max number inputs
  'list'    — categorical; frontend renders multi-select chips
              Omit 'options' → framework collects unique values from entries at runtime
              Supply 'options' → static known set, shown before first run

  Shorthand: write just the type string when you have no extra keys.
    'ip'  is equivalent to  {'type': 'ip'}
  Only use dict form when you need to specify 'options':
    {'type': 'list', 'options': ['GET', 'POST', ...]}

== Legacy pattern ==

If you only implement compute(), everything works unchanged and you get no
auto-filter support. Fine for per-session charts or charts with no useful
slice-able data fields.
"""

import plotly.graph_objects as go
from typing import List

from workspaces.network.research import ResearchChart, Param, AnalysisContext


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
    # Declared params become input fields in the chart runner UI (e.g. target IP).
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

    # ── entry_schema ──────────────────────────────────────────────────────────
    # Declares the filterable fields in your build_data() entries.
    # The frontend renders filter controls based on this — available immediately,
    # before the chart is run for the first time.
    #
    # Shorthand (no extra options needed):
    #   'field': 'ip'        — text input, prefix/exact match
    #   'field': 'string'    — text input, case-insensitive contains
    #   'field': 'numeric'   — min/max number inputs
    #   'field': 'list'      — chips; unique values collected from entries at runtime
    #
    # Dict form (when you need static options):
    #   'field': {'type': 'list', 'options': ['GET', 'POST', 'PUT', ...]}
    #            chips shown immediately with the declared options
    entry_schema = {
        'peer':      'ip',
        'protocol':  'list',
        'direction': {'type': 'list', 'options': ['in', 'out']},
        'bytes':     'numeric',
        'src_port':  'numeric',
        'dst_port':  'numeric',
    }

    # ── build_data() ──────────────────────────────────────────────────────────
    def build_data(self, ctx: AnalysisContext, params: dict) -> List[dict]:
        """
        Collect the raw records you want to plot. One dict per point/bar.

        ctx fields:
          ctx.packets     — list[PacketRecord]  (pre-filtered by time/scope)
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
          .extra           (dict — dissector fields, e.g. extra["dns_query"])

        params: dict keyed by Param.name → str (always a string; cast as needed)

        Use "ts" for the time axis — it is excluded from filter detection.
        All other keys become candidate filter fields.
        """
        ip = params["target_ip"]

        return [
            {
                "ts":       p.timestamp * 1000,   # time axis — excluded from filters
                "peer":     p.dst_ip if p.src_ip == ip else p.src_ip,
                "protocol": p.protocol or p.transport or "OTHER",
                "bytes":    p.orig_len,
                "src_port": p.src_port,
                "dst_port": p.dst_port,
            }
            for p in ctx.packets
            if p.src_ip == ip or p.dst_ip == ip
        ]

    # ── build_figure() ────────────────────────────────────────────────────────
    def build_figure(self, entries: List[dict], params: dict) -> go.Figure:
        """
        Build and return a Plotly figure from the already-filtered entries.

        entries: list of dicts from build_data(), after per-chart filters applied.
        params:  original user params (same as passed to build_data()).

        Return a go.Figure. Do NOT call .to_dict() or apply SWIFTEYE_LAYOUT —
        the framework does both.
        """
        ip = params["target_ip"]

        if not entries:
            fig = go.Figure()
            fig.update_layout(title=f"No packets found for {ip}")
            return fig

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=[e["ts"]    for e in entries],
            y=[e["bytes"] for e in entries],
            mode="markers",
            name="packet size",
            hovertext=[
                f"{e['peer']}  {e['protocol']}<br>Bytes: {e['bytes']:,}"
                for e in entries
            ],
            hovertemplate="%{hovertext}<extra></extra>",
        ))
        fig.update_layout(
            title=f"Packet sizes — {ip}",
            xaxis_title="Time",
            yaxis_title="Bytes",
            xaxis_type="date",
        )
        return fig


# ── Registration ──────────────────────────────────────────────────────────────
# Uncomment and add to backend/server.py → _register_charts() instead.
# Charts are never auto-imported — you must register explicitly.
#
# In server.py:
#   ("workspaces.network.research.my_chart_name", "MyChart"),
#
# from workspaces.network.research import register_chart
# from workspaces.network.research.my_chart_name import MyChart
# register_chart(MyChart())
