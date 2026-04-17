"""
JA4 Fingerprint Timeline — Research Chart

Like the JA3 timeline but uses JA4 hashes — more stable across TLS version
variations and less prone to false positives than JA3.

Chart: X = session start time, Y = remote IP (categorical),
       colour = JA4 hash, size = total bytes (sqrt-scaled, small).
"""

from collections import defaultdict
from typing import List

from workspaces.network.research import ResearchChart, Param, AnalysisContext, SWIFTEYE_LAYOUT

_PALETTE = [
    "#58a6ff", "#3fb950", "#f0883e", "#bc8cff", "#f85149",
    "#2dd4bf", "#d29922", "#79c0ff", "#56d364", "#ffa657",
]


class JA4Timeline(ResearchChart):
    name        = "ja4_timeline"
    title       = "JA4 fingerprint timeline"
    description = "TLS sessions for a target IP — Y = remote IP, colour = JA4 fingerprint, size = bytes"

    params = [
        Param(name="target_ip", label="Target IP", type="ip",
              placeholder="e.g. 192.168.1.177"),
    ]
    entry_schema = {
        'remote_ip': 'ip',
        'ja4':       'string',
        'sni':       'string',
        'tls_ver':   'list',
        'bytes':     'numeric',
        'duration':  'numeric',
        'role':      {'type': 'list', 'options': ['→ (initiator)', '← (responder)']},
    }

    def build_data(self, ctx: AnalysisContext, params: dict) -> List[dict]:
        target = params.get("target_ip", "").strip()

        tls_sessions = [
            s for s in ctx.sessions
            if s.get("ja4_hashes")
            and (s.get("initiator_ip") == target or s.get("responder_ip") == target
                 or target in (s.get("src_ip", ""), s.get("dst_ip", "")))
        ]

        entries = []
        for s in tls_sessions:
            init  = s.get("initiator_ip", s.get("src_ip", ""))
            resp  = s.get("responder_ip", s.get("dst_ip", ""))
            remote = resp if init == target else init
            ts    = s.get("start_time", 0) * 1000
            total = s.get("total_bytes", 0)
            sni   = ", ".join(s.get("tls_snis", [])) or "—"
            ver   = ", ".join(s.get("tls_versions", [])) or "—"
            dur   = round(s.get("duration", 0), 1)
            role  = "→ (initiator)" if init == target else "← (responder)"

            for h in s.get("ja4_hashes", []):
                short = h[:24] + "…" if len(h) > 24 else h
                entries.append({
                    "ts":        ts,
                    "remote_ip": remote,
                    "ja4":       short,
                    "sni":       sni,
                    "tls_ver":   ver,
                    "bytes":     total,
                    "duration":  dur,
                    "role":      role,
                    "_ja4_full": h,
                })
        return entries

    def build_figure(self, entries: List[dict], params: dict):
        import plotly.graph_objects as go

        target = params.get("target_ip", "").strip()

        if not entries:
            fig = go.Figure()
            fig.update_layout(title=f"No TLS sessions with JA4 data found for {target}")
            return fig

        seen_hashes, seen_set = [], set()
        for e in entries:
            h = e["_ja4_full"]
            if h not in seen_set:
                seen_hashes.append(h)
                seen_set.add(h)
        hash_color = {h: _PALETTE[i % len(_PALETTE)] for i, h in enumerate(seen_hashes)}

        def label(h):
            short = h[:24] + "…" if len(h) > 24 else h
            return short

        remote_first = {}
        for e in sorted(entries, key=lambda x: x["ts"]):
            if e["remote_ip"] not in remote_first:
                remote_first[e["remote_ip"]] = e["ts"]
        remote_ips = sorted(remote_first, key=remote_first.get)

        trace_map = defaultdict(lambda: {"x": [], "y": [], "size": [], "text": []})
        for e in entries:
            h    = e["_ja4_full"]
            size = max(5, min(16, (e["bytes"] ** 0.5) * 0.3))
            trace_map[h]["x"].append(e["ts"])
            trace_map[h]["y"].append(e["remote_ip"])
            trace_map[h]["size"].append(size)
            trace_map[h]["text"].append(
                f"<b>{e['remote_ip']}</b><br>"
                f"Role: {e['role']}<br>"
                f"JA4: {e['ja4']}<br>"
                f"SNI: {e['sni']}<br>"
                f"TLS: {e['tls_ver']}<br>"
                f"Bytes: {e['bytes']:,}<br>"
                f"Duration: {e['duration']}s"
            )

        traces = []
        for h, d in trace_map.items():
            traces.append(go.Scatter(
                mode="markers", name=label(h),
                x=d["x"], y=d["y"],
                text=d["text"],
                hovertemplate="%{text}<extra></extra>",
                marker=dict(color=hash_color.get(h, "#8b949e"), size=d["size"],
                            opacity=0.85, line=dict(width=0.5, color="rgba(0,0,0,0.3)")),
            ))

        fig = go.Figure(data=traces)
        fig.update_layout(
            title=dict(
                text=f"JA4 timeline · {target} · {len(entries)} TLS sessions",
                font=dict(color="#e6edf3", size=12),
            ),
            xaxis=dict(title=dict(text="Session start time", font=dict(color="#484f58")),
                       type="date", tickformat="%H:%M:%S"),
            yaxis=dict(title=dict(text="Remote IP", font=dict(color="#484f58")),
                       type="category", categoryorder="array", categoryarray=remote_ips,
                       tickfont=dict(size=9, family="JetBrains Mono, monospace"),
                       automargin=True),
            height=max(300, 80 + len(remote_ips) * 38),
            margin=dict(l=140, r=20, t=50, b=60),
            legend=dict(bgcolor="rgba(14,17,23,0.8)", bordercolor="rgba(48,54,61,0.8)",
                        borderwidth=1, font=dict(size=9, family="JetBrains Mono, monospace"),
                        x=1.01, y=1, xanchor="left", yanchor="top"),
        )
        return fig


def register(registry):
    registry.register(JA4Timeline())
