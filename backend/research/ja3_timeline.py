"""
JA3 Fingerprint Timeline — Research Chart

Question answered:
    Which TLS fingerprints (JA3) did a host use when communicating with remote IPs,
    and how much data was exchanged in each session?

Chart type:
    Scatter plot. X = session start time. Y = remote IP (categorical).
    Colour = JA3 hash (known hashes show the app name in the legend).
    Dot size = total bytes in session (sqrt-scaled).

Useful for:
    - Spotting an unusual JA3 among otherwise normal browser traffic (C2 implant)
    - Seeing which remote IPs a host connects to via TLS and with what fingerprint
    - Detecting JA3 hash changes over time (updated malware, different client)

Input: a local IP address to investigate.
"""

from collections import defaultdict
from research import ResearchChart, Param, AnalysisContext, SWIFTEYE_LAYOUT


# A small palette for up to 10 distinct JA3 colours; cycles if more
_JA3_PALETTE = [
    "#58a6ff", "#3fb950", "#f0883e", "#bc8cff", "#f85149",
    "#2dd4bf", "#d29922", "#79c0ff", "#56d364", "#ffa657",
]


class JA3Timeline(ResearchChart):
    name        = "ja3_timeline"
    title       = "JA3 fingerprint timeline"
    description = "TLS sessions for a target IP — Y = remote IP, colour = JA3 fingerprint, size = bytes"

    params = [
        Param(
            name="target_ip",
            label="Target IP",
            type="ip",
            placeholder="e.g. 192.168.1.177",
        ),
    ]

    def compute(self, ctx: AnalysisContext, params: dict) -> dict:
        target = params.get("target_ip", "").strip()

        # Filter TLS sessions involving target that have at least one JA3 hash
        tls_sessions = [
            s for s in ctx.sessions
            if s.get("ja3_hashes")
            and (s.get("initiator_ip") == target or s.get("responder_ip") == target
                 or target in (s.get("src_ip", ""), s.get("dst_ip", "")))
        ]

        if not tls_sessions:
            return {
                "data": [],
                "layout": {
                    **SWIFTEYE_LAYOUT,
                    "title": {"text": f"No TLS sessions with JA3 data found for {target}",
                              "font": {"color": "#8b949e"}},
                },
            }

        # Build a JA3 → colour + label map
        all_hashes = []
        for s in tls_sessions:
            for h in s.get("ja3_hashes", []):
                if h not in all_hashes:
                    all_hashes.append(h)

        # Look up known app names from ja3_apps lists in sessions
        hash_to_name = {}
        for s in tls_sessions:
            for app in s.get("ja3_apps", []):
                if app.get("hash") and app.get("name"):
                    hash_to_name[app["hash"]] = app["name"]

        hash_color = {}
        for i, h in enumerate(all_hashes):
            hash_color[h] = _JA3_PALETTE[i % len(_JA3_PALETTE)]

        def label(h):
            name = hash_to_name.get(h)
            short = h[:12] + "…"
            return f"{short} ({name})" if name else short

        # Group by remote IP for Y axis ordering
        remote_first_seen = {}
        for s in sorted(tls_sessions, key=lambda x: x.get("start_time", 0)):
            init = s.get("initiator_ip", s.get("src_ip", ""))
            resp = s.get("responder_ip", s.get("dst_ip", ""))
            remote = resp if init == target else init
            if remote not in remote_first_seen:
                remote_first_seen[remote] = s.get("start_time", 0)
        remote_ips = sorted(remote_first_seen, key=lambda r: remote_first_seen[r])

        # Build one trace per JA3 hash
        trace_map = defaultdict(lambda: {"x": [], "y": [], "size": [], "text": []})

        for s in tls_sessions:
            init = s.get("initiator_ip", s.get("src_ip", ""))
            resp = s.get("responder_ip", s.get("dst_ip", ""))
            remote = resp if init == target else init
            ts    = s.get("start_time", 0) * 1000
            total = s.get("total_bytes", 0)
            size  = max(5, min(16, (total ** 0.5) * 0.3))
            sni   = ", ".join(s.get("tls_snis", [])) or "—"
            ver   = ", ".join(s.get("tls_versions", [])) or "—"
            dur   = round(s.get("duration", 0), 1)

            for h in s.get("ja3_hashes", []):
                trace_map[h]["x"].append(ts)
                trace_map[h]["y"].append(remote)
                trace_map[h]["size"].append(size)
                direction = "→ (initiator)" if init == target else "← (responder)"
                trace_map[h]["text"].append(
                    f"<b>{remote}</b><br>"
                    f"Role: {direction}<br>"
                    f"JA3: {h[:20]}…<br>"
                    f"App: {hash_to_name.get(h, 'unknown')}<br>"
                    f"SNI: {sni}<br>"
                    f"TLS: {ver}<br>"
                    f"Bytes: {total:,}<br>"
                    f"Duration: {dur}s"
                )

        traces = []
        for h, d in trace_map.items():
            traces.append({
                "type": "scatter",
                "mode": "markers",
                "name": label(h),
                "x": d["x"],
                "y": d["y"],
                "text": d["text"],
                "hovertemplate": "%{text}<extra></extra>",
                "marker": {
                    "color": hash_color.get(h, "#8b949e"),
                    "size": d["size"],
                    "opacity": 0.85,
                    "line": {"width": 0.5, "color": "rgba(0,0,0,0.3)"},
                },
            })

        height = max(300, 80 + len(remote_ips) * 38)

        layout = {
            **SWIFTEYE_LAYOUT,
            "title": {
                "text": f"JA3 timeline · {target} · {len(tls_sessions)} TLS sessions",
                "font": {"color": "#e6edf3", "size": 12},
            },
            "xaxis": {
                **SWIFTEYE_LAYOUT["xaxis"],
                "title": {"text": "Session start time", "font": {"color": "#484f58"}},
                "type": "date",
                "tickformat": "%H:%M:%S",
            },
            "yaxis": {
                **SWIFTEYE_LAYOUT["yaxis"],
                "title": {"text": "Remote IP", "font": {"color": "#484f58"}},
                "type": "category",
                "categoryorder": "array",
                "categoryarray": remote_ips,
                "tickfont": {"size": 9, "family": "JetBrains Mono, monospace"},
                "automargin": True,
            },
            "height": height,
            "margin": {"l": 140, "r": 20, "t": 50, "b": 60},
            "legend": {
                "bgcolor":     "rgba(14,17,23,0.8)",
                "bordercolor": "rgba(48,54,61,0.8)",
                "borderwidth": 1,
                "font":        {"size": 9, "family": "JetBrains Mono, monospace"},
                "x": 1.01, "y": 1,
                "xanchor": "left", "yanchor": "top",
            },
        }

        return {"data": traces, "layout": layout}


def register(registry):
    registry.register(JA3Timeline())
