"""
Node Centrality Analysis

Computes degree centrality, betweenness centrality (Brandes algorithm),
and traffic-weighted scores for all nodes. Returns a ranked table.

This replaces the client-side JavaScript Brandes implementation that was
in AnalysisPage.jsx — same algorithm, but runs in Python so it scales
to larger graphs and researchers don't need to touch frontend code.
"""

from collections import defaultdict, deque
from workspaces.network.plugins.analyses import AnalysisPluginBase
from workspaces.network.plugins import display_table, display_text


class NodeCentralityAnalysis(AnalysisPluginBase):
    name        = "node_centrality"
    title       = "Node Centrality"
    description = "Ranks nodes by degree, betweenness, and traffic volume."
    icon        = "🔗"
    version     = "1.0"

    def compute(self, ctx) -> dict:
        nodes = ctx.nodes or []
        edges = ctx.edges or []

        if not nodes or not edges:
            return {
                "_display": [display_text("No graph data available. Load a capture first.")],
                "ranked": [],
            }

        node_ids = {n["id"] for n in nodes}
        node_map = {n["id"]: n for n in nodes}

        # Build adjacency
        adj = defaultdict(set)
        for e in edges:
            s = e.get("source", {})
            t = e.get("target", {})
            sid = s.get("id", s) if isinstance(s, dict) else s
            tid = t.get("id", t) if isinstance(t, dict) else t
            if sid in node_ids and tid in node_ids:
                adj[sid].add(tid)
                adj[tid].add(sid)

        # Brandes betweenness centrality
        betweenness = {nid: 0.0 for nid in node_ids}
        for src in node_ids:
            stack = []
            pred = {nid: [] for nid in node_ids}
            sigma = {nid: 0 for nid in node_ids}
            dist = {nid: -1 for nid in node_ids}
            sigma[src] = 1
            dist[src] = 0
            queue = deque([src])

            while queue:
                v = queue.popleft()
                stack.append(v)
                for w in adj.get(v, set()):
                    if dist[w] < 0:
                        queue.append(w)
                        dist[w] = dist[v] + 1
                    if dist[w] == dist[v] + 1:
                        sigma[w] += sigma[v]
                        pred[w].append(v)

            delta = {nid: 0.0 for nid in node_ids}
            while stack:
                w = stack.pop()
                for v in pred[w]:
                    delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
                if w != src:
                    betweenness[w] += delta[w]

        n = len(node_ids)
        norm_b = max(1, (n - 1) * (n - 2) / 2)
        max_deg = max(1, n - 1)
        max_bytes = max(1, max((node_map[nid].get("total_bytes") or 0) for nid in node_ids))
        max_btw = max(1.0, max(betweenness.values()))

        ranked = []
        for nid in node_ids:
            nd = node_map[nid]
            deg = len(adj.get(nid, set()))
            btw = betweenness[nid] / norm_b
            byt = (nd.get("total_bytes") or 0) / max_bytes
            deg_norm = deg / max_deg
            btw_norm = betweenness[nid] / max_btw
            score = (deg_norm + btw_norm + byt) / 3

            label = (nd.get("metadata", {}) or {}).get("name") or ""
            if not label:
                hostnames = nd.get("hostnames") or []
                label = hostnames[0] if hostnames else nid

            ranked.append({
                "id": nid,
                "label": label,
                "degree": deg,
                "degree_norm": round(deg_norm, 4),
                "betweenness_norm": round(btw_norm, 4),
                "bytes_norm": round(byt, 4),
                "total_bytes": nd.get("total_bytes") or 0,
                "score": round(score, 4),
                "ips": nd.get("ips") or [nid],
            })

        ranked.sort(key=lambda r: r["score"], reverse=True)

        # Build display table — top 50
        headers = ["#", "Node", "Score", "Degree", "Betweenness", "Bytes"]
        rows = []
        for i, r in enumerate(ranked[:50]):
            rows.append([
                str(i + 1),
                r["label"],
                str(round(r["score"] * 100)),
                str(r["degree"]),
                f"{r['betweenness_norm'] * 100:.1f}%",
                _fmt_bytes(r["total_bytes"]),
            ])

        return {
            "_display": [
                display_table(headers, rows),
                display_text(f"{len(ranked)} nodes ranked · composite score = (degree + betweenness + traffic) / 3"),
            ],
            "ranked": ranked,
        }


def _fmt_bytes(b):
    if b < 1024:
        return f"{b} B"
    if b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    if b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    return f"{b / (1024 * 1024 * 1024):.2f} GB"
