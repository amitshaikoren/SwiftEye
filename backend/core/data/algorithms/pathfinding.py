"""
Graph pathfinding for SwiftEye.

Finds paths between two nodes on the raw (unclustered) graph.
Returns aggregated hop-layer and edge-set data (not individual paths).
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Dict, List, Optional

import networkx as nx

from .graph_core import build_nx_graph

logger = logging.getLogger(__name__)

# Hard ceiling to avoid runaway computation on dense graphs
MAX_PATHS = 20
MAX_CUTOFF = 10


def _build_directed_graph(nodes: List[Dict], edges: List[Dict]) -> nx.DiGraph:
    """Build a directed networkx graph from SwiftEye node/edge dicts.

    Each SwiftEye edge has a source and target (initiator / responder),
    so the direction is meaningful for protocol analysis.
    """
    G = nx.DiGraph()
    for n in nodes:
        G.add_node(n["id"])
    for e in edges:
        src = e["source"]["id"] if isinstance(e["source"], dict) else e["source"]
        tgt = e["target"]["id"] if isinstance(e["target"], dict) else e["target"]
        weight = e.get("total_bytes", 1) or 1
        if G.has_edge(src, tgt):
            G[src][tgt]["weight"] += weight
        else:
            G.add_edge(src, tgt, weight=weight)
    return G


def find_paths(
    nodes: List[Dict],
    edges: List[Dict],
    source: str,
    target: str,
    cutoff: int = 5,
    max_paths: int = 10,
    directed: bool = False,
) -> Dict:
    """Find simple paths and return aggregated hop/edge data.

    Returns a dict with:
      - source, target, directed
      - path_count: how many paths were found (up to max_paths)
      - hop_layers: {distance_str: [node_ids]} from BFS perspective
      - edges: [{source, target, protocols, total_bytes, session_count}]
      - nodes: [node_id] — all unique nodes on any path
    """
    cutoff = min(cutoff, MAX_CUTOFF)
    max_paths = min(max_paths, MAX_PATHS)

    if directed:
        G = _build_directed_graph(nodes, edges)
    else:
        G = build_nx_graph(nodes, edges)

    result = {
        "source": source,
        "target": target,
        "directed": directed,
        "path_count": 0,
        "hop_layers": {},
        "edges": [],
        "nodes": [],
    }

    if source not in G or target not in G:
        return result

    # Collect all simple paths
    raw_paths = []
    try:
        for path in nx.all_simple_paths(G, source, target, cutoff=cutoff):
            raw_paths.append(path)
            if len(raw_paths) >= max_paths:
                break
    except nx.NetworkXError as exc:
        logger.warning("Pathfinding failed: %s", exc)
        return result

    if not raw_paths:
        return result

    # --- Aggregate unique nodes and edges across all paths ---
    all_nodes = set()
    # edge_key -> set of path indices (to count how many paths use each edge)
    edge_pairs = set()

    for path in raw_paths:
        for node_id in path:
            all_nodes.add(node_id)
        for i in range(len(path) - 1):
            a, b = path[i], path[i + 1]
            edge_pairs.add((a, b))

    # --- Compute hop layers via BFS from source (on the subgraph of path nodes) ---
    # Use min hop distance from source across all paths for each node
    min_hop = {}
    for path in raw_paths:
        for i, node_id in enumerate(path):
            if node_id not in min_hop or i < min_hop[node_id]:
                min_hop[node_id] = i

    hop_layers = defaultdict(list)
    for node_id, dist in sorted(min_hop.items(), key=lambda x: x[1]):
        hop_layers[str(dist)].append(node_id)

    # --- Build edge detail from the original SwiftEye edges ---
    # Create a lookup for quick edge metadata access
    edge_lookup = {}  # (src, tgt) -> aggregated info
    for e in edges:
        src = e["source"]["id"] if isinstance(e["source"], dict) else e["source"]
        tgt = e["target"]["id"] if isinstance(e["target"], dict) else e["target"]
        key = (src, tgt)
        rev_key = (tgt, src)

        for k in [key, rev_key] if not directed else [key]:
            if k not in edge_lookup:
                edge_lookup[k] = {
                    "source": k[0],
                    "target": k[1],
                    "protocols": [],
                    "total_bytes": 0,
                    "session_count": 0,
                }
            info = edge_lookup[k]
            proto = e.get("protocol") or e.get("label") or "unknown"
            if proto not in info["protocols"]:
                info["protocols"].append(proto)
            info["total_bytes"] += e.get("total_bytes", 0) or 0
            info["session_count"] += e.get("session_count", 0) or 0

    path_edges = []
    seen_edges = set()
    for a, b in edge_pairs:
        key = (a, b)
        rev_key = (b, a)
        lookup_key = key if key in edge_lookup else rev_key if rev_key in edge_lookup else None
        if lookup_key and lookup_key not in seen_edges:
            seen_edges.add(lookup_key)
            # Also mark reverse to avoid duplicates in undirected mode
            if not directed:
                seen_edges.add((lookup_key[1], lookup_key[0]))
            path_edges.append(edge_lookup[lookup_key])

    result["path_count"] = len(raw_paths)
    result["hop_layers"] = dict(hop_layers)
    result["edges"] = path_edges
    result["nodes"] = list(all_nodes)

    logger.info(
        "Pathfinding %s → %s (cutoff=%d, directed=%s): %d path(s), %d nodes, %d edges",
        source, target, cutoff, directed, len(raw_paths), len(all_nodes), len(path_edges),
    )
    return result
