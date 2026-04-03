"""
DNS Query Timeline — Research Chart

Question answered:
    Which domains were queried, when, and what was the response?

Chart type:
    Scatter plot. X = time. Y = domain name (categorical, one row per unique domain).
    Colour = response code: NOERROR green, NXDOMAIN red, SERVFAIL orange,
             REFUSED purple, query (no response yet) grey.
    Dot size = uniform (domain name is the key info, not bytes).

Useful for:
    - DGA detection: spray of NXDOMAINs in a short time window
    - C2 beaconing: same domain queried repeatedly at regular intervals
    - Suspicious domains: unexpected NXDOMAINs for known-good names
    - DNS tunneling: high query rate to a single domain
"""

from collections import defaultdict
from typing import List

from research import ResearchChart, Param, AnalysisContext, SWIFTEYE_LAYOUT


_RCODE_COLOR = {
    0: "#3fb950",
    2: "#f0883e",
    3: "#f85149",
    5: "#bc8cff",
}
_RCODE_NAME = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
    3: "NXDOMAIN", 4: "NOTIMP",  5: "REFUSED",
}
_DEFAULT_COLOR = "#8b949e"


class DNSTimeline(ResearchChart):
    name        = "dns_timeline"
    title       = "DNS query timeline"
    description = "All DNS queries over time — Y = domain, colour = response code. NXDOMAINs in red, NOERROR green."

    params = []
    entry_schema = {
        'domain':  'string',
        'status':  {'type': 'list', 'options': ['NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED', 'query']},
        'qtype':   {'type': 'list', 'options': ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'PTR', 'SRV', 'NS', 'SOA']},
        'client':  'ip',
        'answers': 'string',
    }

    def build_data(self, ctx: AnalysisContext, params: dict) -> List[dict]:
        entries = []
        for pkt in ctx.packets:
            ex = pkt.extra
            if not ex.get("dns_query"):
                continue
            domain  = ex["dns_query"].lower().rstrip(".")
            rcode   = ex.get("dns_rcode")
            qr      = ex.get("dns_qr", "query")
            qtype   = ex.get("dns_qtype", 1)
            answers = ex.get("dns_answers", [])

            if qr == "query":
                status = "query"
            else:
                status = _RCODE_NAME.get(rcode, f"rcode={rcode}") if rcode is not None else "response"

            entries.append({
                "ts":       pkt.timestamp * 1000,
                "domain":   domain,
                "status":   status,
                "qtype":    _qtype(qtype),
                "client":   pkt.src_ip,
                "server":   pkt.dst_ip,
                "answers":  ", ".join(answers[:5]) if answers else "—",
            })
        return entries

    def build_figure(self, entries: List[dict], params: dict):
        import plotly.graph_objects as go

        if not entries:
            fig = go.Figure()
            fig.update_layout(title="No DNS packets found in capture")
            return fig

        entries = sorted(entries, key=lambda e: e["ts"])

        seen_domains, seen_set = [], set()
        for e in entries:
            if e["domain"] not in seen_set:
                seen_domains.append(e["domain"])
                seen_set.add(e["domain"])

        # Map status → color
        status_color = {
            "NXDOMAIN": _RCODE_COLOR[3],
            "SERVFAIL":  _RCODE_COLOR[2],
            "REFUSED":   _RCODE_COLOR[5],
            "NOERROR":   _RCODE_COLOR[0],
            "query":     _DEFAULT_COLOR,
        }

        trace_map = defaultdict(lambda: {"x": [], "y": [], "text": [], "color": _DEFAULT_COLOR})
        for e in entries:
            s = e["status"]
            trace_map[s]["x"].append(e["ts"])
            trace_map[s]["y"].append(e["domain"])
            trace_map[s]["color"] = status_color.get(s, _DEFAULT_COLOR)
            trace_map[s]["text"].append(
                f"<b>{e['domain']}</b><br>"
                f"Type: {e['qtype']}<br>"
                f"Status: {s}<br>"
                f"Answers: {e['answers']}<br>"
                f"Client: {e['client']}<br>"
                f"Server: {e['server']}"
            )

        order = ["NXDOMAIN", "SERVFAIL", "REFUSED", "NOERROR", "query"]
        traces = []
        for label in order + [k for k in trace_map if k not in order]:
            if label not in trace_map:
                continue
            d = trace_map[label]
            traces.append(go.Scatter(
                mode="markers", name=label,
                x=d["x"], y=d["y"],
                text=d["text"],
                hovertemplate="%{text}<extra></extra>",
                marker=dict(color=d["color"], size=8, opacity=0.85, line=dict(width=0)),
            ))

        height = max(300, 80 + len(seen_domains) * 22)
        fig = go.Figure(data=traces)
        fig.update_layout(
            title=dict(
                text=f"DNS query timeline · {len(entries)} queries · {len(seen_domains)} domains",
                font=dict(color="#e6edf3", size=12),
            ),
            xaxis=dict(title=dict(text="Time", font=dict(color="#484f58")),
                       type="date", tickformat="%H:%M:%S"),
            yaxis=dict(title=dict(text="Domain", font=dict(color="#484f58")),
                       type="category", categoryorder="array",
                       categoryarray=list(reversed(seen_domains)),
                       tickfont=dict(size=9, family="JetBrains Mono, monospace"),
                       automargin=True),
            height=height,
            margin=dict(l=200, r=20, t=50, b=60),
            legend=dict(bgcolor="rgba(14,17,23,0.8)", bordercolor="rgba(48,54,61,0.8)",
                        borderwidth=1, font=dict(size=10),
                        x=1.01, y=1, xanchor="left", yanchor="top"),
        )
        return fig


def _qtype(v: int) -> str:
    return {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
            15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}.get(v, str(v))


def register(registry):
    registry.register(DNSTimeline())
