"""
Graph clustering algorithms for SwiftEye.

Each function takes a list of nodes and edges (as returned by build_graph)
and returns a dict mapping node_id → cluster_id.  Nodes not assigned to any
cluster (singletons) are omitted from the result — the frontend treats
missing entries as "no cluster."

All algorithms are lightweight and run in <50ms for graphs under 1000 nodes.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional

import networkx as nx

from .graph_core import build_nx_graph

logger = logging.getLogger(__name__)


def _label_clusters(groups: List[set]) -> Dict[str, int]:
    """Convert a list of node-id sets into a flat node→cluster_id mapping.
    Only groups with 2+ members are included (singletons are unclustered)."""
    result = {}
    cid = 0
    for group in sorted(groups, key=len, reverse=True):
        if len(group) < 2:
            continue
        for node_id in group:
            result[node_id] = cid
        cid += 1
    return result


# ── Algorithms ───────────────────────────────────────────────────────

def louvain_clusters(
    nodes: List[Dict], edges: List[Dict],
    resolution: float = 1.0,
    min_size: int = 2,
) -> Dict[str, int]:
    """Louvain community detection — groups nodes that are more densely
    connected internally than externally.  Good general-purpose default.

    `resolution` > 1 produces more/smaller communities;
    `resolution` < 1 produces fewer/larger communities.
    """
    G = build_nx_graph(nodes, edges)
    if G.number_of_nodes() == 0:
        return {}
    communities = nx.community.louvain_communities(
        G, weight="weight", resolution=resolution, seed=42,
    )
    return _label_clusters([c for c in communities if len(c) >= min_size])


def kcore_clusters(
    nodes: List[Dict], edges: List[Dict],
    min_k: int = 3,
) -> Dict[str, int]:
    """K-core decomposition — peels away low-degree nodes, keeps the dense
    core.  Returns connected components of the k-core as clusters.
    Nodes outside the core are unclustered (visible but not grouped).

    `min_k` is the minimum degree threshold.  Higher = denser core.
    """
    G = build_nx_graph(nodes, edges)
    if G.number_of_nodes() == 0:
        return {}
    try:
        core = nx.k_core(G, k=min_k)
    except nx.NetworkXError:
        # Graph has no k-core at this threshold
        return {}
    components = list(nx.connected_components(core))
    return _label_clusters(components)


def hub_spoke_clusters(
    nodes: List[Dict], edges: List[Dict],
    min_spokes: int = 4,
) -> Dict[str, int]:
    """Hub-and-spoke collapse — finds high-degree nodes and groups their
    leaf neighbors (degree 1 in the full graph) into a cluster around
    the hub.  Best for star patterns like many-clients → one-server.

    `min_spokes` is the minimum number of leaf neighbors to form a cluster.
    """
    G = build_nx_graph(nodes, edges)
    if G.number_of_nodes() == 0:
        return {}

    result = {}
    cid = 0
    # Sort by degree descending so the biggest hubs claim leaves first
    for hub, deg in sorted(G.degree(), key=lambda x: x[1], reverse=True):
        if deg < min_spokes:
            continue
        leaves = [
            nbr for nbr in G.neighbors(hub)
            if G.degree(nbr) == 1 and nbr not in result
        ]
        if len(leaves) < min_spokes:
            continue
        # Cluster = only the leaves (hub stays as a regular node with an
        # edge to the cluster mega-node)
        for leaf in leaves:
            result[leaf] = cid
        cid += 1

    return result


def shared_neighbor_clusters(
    nodes: List[Dict], edges: List[Dict],
    min_size: int = 3,
) -> Dict[str, int]:
    """Shared-neighbor grouping — groups nodes that connect to the exact
    same set of peers (structural equivalence).  Best for hosts with
    identical communication patterns (e.g. many DHCP/DNS clients).

    `min_size` is the minimum group size to form a cluster.
    """
    G = build_nx_graph(nodes, edges)
    if G.number_of_nodes() == 0:
        return {}

    # Build neighbor-set fingerprint for each node
    fingerprints = defaultdict(set)
    for node in G.nodes():
        nbrs = frozenset(G.neighbors(node))
        if nbrs:  # skip isolated nodes
            fingerprints[nbrs].add(node)

    groups = [group for group in fingerprints.values() if len(group) >= min_size]
    return _label_clusters(groups)


# ── Dispatcher ───────────────────────────────────────────────────────

ALGORITHMS = {
    "louvain": louvain_clusters,
    "kcore": kcore_clusters,
    "hub_spoke": hub_spoke_clusters,
    "shared_neighbor": shared_neighbor_clusters,
}

def compute_clusters(
    nodes: List[Dict],
    edges: List[Dict],
    algorithm: str = "louvain",
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, int]:
    """Dispatch to the requested clustering algorithm.

    Returns: dict mapping node_id → cluster_id.
    Nodes not in any cluster are omitted.
    """
    func = ALGORITHMS.get(algorithm)
    if not func:
        raise ValueError(f"Unknown clustering algorithm: {algorithm!r}. "
                         f"Available: {', '.join(ALGORITHMS)}")
    kwargs = params or {}
    result = func(nodes, edges, **kwargs)
    logger.info("Clustering [%s]: %d nodes → %d clusters",
                algorithm, len(nodes), len(set(result.values())))
    return result


# ── Graph collapsing ─────────────────────────────────────────────────

def collapse_clusters(
    nodes: List[Dict],
    edges: List[Dict],
    clusters: Dict[str, int],
) -> tuple:
    """Collapse clustered nodes into mega-nodes and rewrite edges.

    Returns (new_nodes, new_edges) where:
    - Each cluster becomes a single mega-node with aggregated stats
    - Unclustered nodes pass through unchanged
    - Edges pointing to clustered nodes are rewritten to point to the
      mega-node, with duplicates merged (bytes/packets summed)
    """
    if not clusters:
        return nodes, edges

    # Group nodes by cluster_id
    cluster_members: Dict[int, List[Dict]] = defaultdict(list)
    unclustered = []
    node_to_cluster: Dict[str, str] = {}  # node_id → mega-node id

    for node in nodes:
        cid = clusters.get(node["id"])
        if cid is not None:
            cluster_members[cid].append(node)
            node_to_cluster[node["id"]] = f"cluster:{cid}"
        else:
            unclustered.append(node)

    # Build mega-nodes
    mega_nodes = []
    for cid, members in sorted(cluster_members.items()):
        all_ips = set()
        all_macs = set()
        all_protocols = set()
        all_hostnames = set()
        total_bytes = 0
        packet_count = 0

        for m in members:
            all_ips.update(m.get("ips", [m["id"]]))
            all_macs.update(m.get("macs", []))
            all_protocols.update(m.get("protocols", []))
            all_hostnames.update(m.get("hostnames", []))
            total_bytes += m.get("total_bytes", 0)
            packet_count += m.get("packet_count", 0)

        mega_id = f"cluster:{cid}"
        # Pick a representative label: most common hostname, or IP range summary
        member_ids = [m["id"] for m in members]
        label = f"{len(members)} nodes"

        mega_nodes.append({
            "id": mega_id,
            "is_cluster": True,
            "is_subnet": False,
            "cluster_id": cid,
            "member_count": len(members),
            "member_ids": member_ids,
            "ips": sorted(all_ips),
            "macs": sorted(all_macs),
            "mac_vendors": [],
            "protocols": sorted(all_protocols),
            "total_bytes": total_bytes,
            "packet_count": packet_count,
            "hostnames": sorted(all_hostnames),
            "is_private": any(m.get("is_private") for m in members),
            "label": label,
        })

    new_nodes = unclustered + mega_nodes

    # Rewrite edges: remap endpoints, merge duplicates
    edge_map: Dict[str, Dict] = {}
    for e in edges:
        src = e["source"]["id"] if isinstance(e["source"], dict) else e["source"]
        tgt = e["target"]["id"] if isinstance(e["target"], dict) else e["target"]
        # Remap to mega-node if clustered
        src = node_to_cluster.get(src, src)
        tgt = node_to_cluster.get(tgt, tgt)
        # Skip self-loops (both ends in same cluster)
        if src == tgt:
            continue
        # Canonical edge key
        ek = tuple(sorted([src, tgt]))
        edge_key = f"{ek[0]}|{ek[1]}|{e.get('protocol', '')}"

        if edge_key in edge_map:
            existing = edge_map[edge_key]
            existing["total_bytes"] += e.get("total_bytes", 0)
            existing["packet_count"] += e.get("packet_count", 0)
            existing["ports"] = sorted(set(existing.get("ports", []) + e.get("ports", [])))[:20]
            existing["src_ports"] = sorted(set(existing.get("src_ports", []) + e.get("src_ports", [])))[:20]
            existing["dst_ports"] = sorted(set(existing.get("dst_ports", []) + e.get("dst_ports", [])))[:20]
        else:
            edge_map[edge_key] = {
                **e,
                "id": edge_key,
                "source": ek[0],
                "target": ek[1],
                "total_bytes": e.get("total_bytes", 0),
                "packet_count": e.get("packet_count", 0),
            }

    new_edges = list(edge_map.values())

    logger.info("Collapsed %d clusters: %d nodes → %d, %d edges → %d",
                len(cluster_members), len(nodes), len(new_nodes),
                len(edges), len(new_edges))

    return new_nodes, new_edges
