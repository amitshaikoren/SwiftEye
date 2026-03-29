"""
Shared graph construction utilities for SwiftEye.

All graph-theory modules (clustering, pathfinding, centrality, etc.)
build on the same networkx graph.  This module owns the conversion
from SwiftEye node/edge dicts to a networkx Graph.
"""

from __future__ import annotations

from typing import Dict, List

import networkx as nx


def build_nx_graph(nodes: List[Dict], edges: List[Dict]) -> nx.Graph:
    """Build an undirected networkx graph from SwiftEye node/edge dicts.

    Edges are weighted by ``total_bytes`` (summed when the same pair
    appears with different protocols).
    """
    G = nx.Graph()
    for n in nodes:
        G.add_node(n["id"])
    for e in edges:
        src = e["source"]["id"] if isinstance(e["source"], dict) else e["source"]
        tgt = e["target"]["id"] if isinstance(e["target"], dict) else e["target"]
        weight = e.get("total_bytes", 1) or 1
        # Multiple edges between same pair (different protocols) → sum weights
        if G.has_edge(src, tgt):
            G[src][tgt]["weight"] += weight
        else:
            G.add_edge(src, tgt, weight=weight)
    return G
