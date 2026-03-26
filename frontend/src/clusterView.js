/**
 * Client-side cluster view transform.
 *
 * Takes the raw (unmutated) graph data + cluster assignments from the backend
 * and produces a "view" graph with mega-nodes and rewritten edges.
 *
 * This is a VIEW TRANSFORM — it never modifies the original data.
 * The raw graph is always preserved in memory for instant toggle-off,
 * pathfinding on the real graph, etc.
 */

/** 12 visually distinct cluster colors (shared by GraphCanvas + ClusterLegend). */
export const CLUSTER_COLORS = [
  '#58a6ff', '#3fb950', '#d29922', '#f85149', '#bc8cff', '#f0883e',
  '#39d2c0', '#db61a2', '#79c0ff', '#7ee787', '#e3b341', '#ff7b72',
];

/**
 * Apply cluster assignments to produce a clustered view of the graph.
 *
 * @param {Array} nodes    - Original graph nodes
 * @param {Array} edges    - Original graph edges
 * @param {Object} clusters - Map of node_id -> cluster_id (from backend)
 * @param {Set} [exclusions] - Set of cluster_ids to leave expanded (not collapsed)
 * @returns {{ nodes: Array, edges: Array }}
 */
export function applyClusterView(nodes, edges, clusters, exclusions) {
  if (!clusters || Object.keys(clusters).length === 0) {
    return { nodes, edges };
  }

  // Group nodes by cluster_id
  const clusterMembers = {};  // cluster_id -> [node, ...]
  const unclustered = [];
  const nodeToCluster = {};   // node_id -> mega-node id

  for (const node of nodes) {
    const cid = clusters[node.id];
    if (cid != null && !exclusions?.has(cid)) {
      if (!clusterMembers[cid]) clusterMembers[cid] = [];
      clusterMembers[cid].push(node);
      nodeToCluster[node.id] = `cluster:${cid}`;
    } else {
      unclustered.push(node);
    }
  }

  // Build mega-nodes
  const megaNodes = [];
  for (const [cidStr, members] of Object.entries(clusterMembers)) {
    const cid = Number(cidStr);
    const allIps = new Set();
    const allMacs = new Set();
    const allProtocols = new Set();
    const allHostnames = new Set();
    let totalBytes = 0;
    let packetCount = 0;

    for (const m of members) {
      for (const ip of (m.ips || [m.id])) allIps.add(ip);
      for (const mac of (m.macs || [])) allMacs.add(mac);
      for (const p of (m.protocols || [])) allProtocols.add(p);
      for (const h of (m.hostnames || [])) allHostnames.add(h);
      totalBytes += m.total_bytes || 0;
      packetCount += m.packet_count || 0;
    }

    const memberIds = members.map(m => m.id);

    megaNodes.push({
      id: `cluster:${cid}`,
      is_cluster: true,
      is_subnet: false,
      cluster_id: cid,
      member_count: members.length,
      member_ids: memberIds,
      ips: [...allIps].sort(),
      macs: [...allMacs].sort(),
      mac_vendors: [],
      protocols: [...allProtocols].sort(),
      total_bytes: totalBytes,
      packet_count: packetCount,
      hostnames: [...allHostnames].sort(),
      is_private: members.some(m => m.is_private),
      label: `${members.length} nodes`,
    });
  }

  const viewNodes = [...unclustered, ...megaNodes];

  // Rewrite edges: remap endpoints to mega-nodes, merge duplicates
  const edgeMap = {};
  for (const e of edges) {
    let src = e.source?.id ?? e.source;
    let tgt = e.target?.id ?? e.target;

    // Remap to mega-node if clustered
    src = nodeToCluster[src] || src;
    tgt = nodeToCluster[tgt] || tgt;

    // Skip self-loops (both ends in same cluster)
    if (src === tgt) continue;

    // Canonical edge key (sorted endpoints + protocol)
    const ek = [src, tgt].sort();
    const edgeKey = `${ek[0]}|${ek[1]}|${e.protocol || ''}`;

    if (edgeMap[edgeKey]) {
      const existing = edgeMap[edgeKey];
      existing.total_bytes += e.total_bytes || 0;
      existing.packet_count += e.packet_count || 0;
      const portSet = new Set([...(existing.ports || []), ...(e.ports || [])]);
      existing.ports = [...portSet].slice(0, 20);
    } else {
      edgeMap[edgeKey] = {
        ...e,
        id: edgeKey,
        source: ek[0],
        target: ek[1],
        total_bytes: e.total_bytes || 0,
        packet_count: e.packet_count || 0,
      };
    }
  }

  const viewEdges = Object.values(edgeMap);

  return { nodes: viewNodes, edges: viewEdges };
}
