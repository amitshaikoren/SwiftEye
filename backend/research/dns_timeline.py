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
from research import ResearchChart, Param, AnalysisContext, SWIFTEYE_LAYOUT


_RCODE_COLOR = {
    0: "#3fb950",   # NOERROR — green
    2: "#f0883e",   # SERVFAIL — orange
    3: "#f85149",   # NXDOMAIN — red
    5: "#bc8cff",   # REFUSED — purple
}
_RCODE_NAME = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}
_DEFAULT_COLOR = "#8b949e"  # query / unknown


class DNSTimeline(ResearchChart):
    name        = "dns_timeline"
    title       = "DNS query timeline"
    description = "All DNS queries over time — Y = domain, colour = response code. NXDOMAINs in red, NOERROR green."

    params = []  # No params — uses all DNS packets in capture

    def compute(self, ctx: AnalysisContext, params: dict) -> dict:
        # Collect one entry per DNS response packet that has a query name
        # (responses carry both the question and the rcode)
        entries = []
        for pkt in ctx.packets:
            ex = pkt.extra
            if not ex.get("dns_query"):
                continue
            domain = ex["dns_query"].lower().rstrip(".")
            rcode  = ex.get("dns_rcode")           # int or None
            qr     = ex.get("dns_qr", "query")     # "query" | "response"
            qtype  = ex.get("dns_qtype", 1)
            answers = ex.get("dns_answers", [])

            entries.append({
                "ts":      pkt.timestamp * 1000,   # ms for Plotly date axis
                "domain":  domain,
                "rcode":   rcode,
                "qr":      qr,
                "qtype":   qtype,
                "answers": answers,
                "src":     pkt.src_ip,
                "dst":     pkt.dst_ip,
            })

        if not entries:
            return {
                "data": [],
                "layout": {
                    **SWIFTEYE_LAYOUT,
                    "title": {"text": "No DNS packets found in capture",
                              "font": {"color": "#8b949e"}},
                },
            }

        # Sort by time
        entries.sort(key=lambda e: e["ts"])

        # Unique domains sorted by first-seen time
        seen_domains = []
        seen_set = set()
        for e in entries:
            if e["domain"] not in seen_set:
                seen_domains.append(e["domain"])
                seen_set.add(e["domain"])

        # Build one trace per (rcode_label) so legend is clean
        trace_map = defaultdict(lambda: {"x": [], "y": [], "text": [], "color": None})

        for e in entries:
            rcode = e["rcode"]
            # Queries (no rcode yet) and responses get separate labels
            if e["qr"] == "query":
                label = "query"
                color = _DEFAULT_COLOR
            else:
                label = _RCODE_NAME.get(rcode, f"rcode={rcode}") if rcode is not None else "response"
                color = _RCODE_COLOR.get(rcode, _DEFAULT_COLOR)

            trace_map[label]["x"].append(e["ts"])
            trace_map[label]["y"].append(e["domain"])
            trace_map[label]["color"] = color

            answers_str = ", ".join(e["answers"][:5]) if e["answers"] else "—"
            trace_map[label]["text"].append(
                f"<b>{e['domain']}</b><br>"
                f"Type: {_qtype(e['qtype'])}<br>"
                f"Status: {label}<br>"
                f"Answers: {answers_str}<br>"
                f"Client: {e['src']}<br>"
                f"Server: {e['dst']}"
            )

        # Order: NXDOMAIN first (most interesting), then SERVFAIL, NOERROR, query
        order = ["NXDOMAIN", "SERVFAIL", "REFUSED", "NOERROR", "query"]
        traces = []
        for label in order + [k for k in trace_map if k not in order]:
            if label not in trace_map:
                continue
            d = trace_map[label]
            traces.append({
                "type": "scatter",
                "mode": "markers",
                "name": label,
                "x": d["x"],
                "y": d["y"],
                "text": d["text"],
                "hovertemplate": "%{text}<extra></extra>",
                "marker": {
                    "color": d["color"],
                    "size": 8,
                    "opacity": 0.85,
                    "line": {"width": 0},
                },
            })

        height = max(300, 80 + len(seen_domains) * 22)

        layout = {
            **SWIFTEYE_LAYOUT,
            "title": {
                "text": f"DNS query timeline · {len(entries)} queries · {len(seen_domains)} domains",
                "font": {"color": "#e6edf3", "size": 12},
            },
            "xaxis": {
                **SWIFTEYE_LAYOUT["xaxis"],
                "title": {"text": "Time", "font": {"color": "#484f58"}},
                "type": "date",
                "tickformat": "%H:%M:%S",
            },
            "yaxis": {
                **SWIFTEYE_LAYOUT["yaxis"],
                "title": {"text": "Domain", "font": {"color": "#484f58"}},
                "type": "category",
                "categoryorder": "array",
                "categoryarray": list(reversed(seen_domains)),  # newest at top
                "tickfont": {"size": 9, "family": "JetBrains Mono, monospace"},
                "automargin": True,
            },
            "height": height,
            "margin": {"l": 200, "r": 20, "t": 50, "b": 60},
            "legend": {
                "bgcolor":     "rgba(14,17,23,0.8)",
                "bordercolor": "rgba(48,54,61,0.8)",
                "borderwidth": 1,
                "font":        {"size": 10},
                "x": 1.01, "y": 1,
                "xanchor": "left", "yanchor": "top",
            },
        }

        return {"data": traces, "layout": layout}


def _qtype(v: int) -> str:
    return {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
            15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}.get(v, str(v))


def register(registry):
    registry.register(DNSTimeline())
