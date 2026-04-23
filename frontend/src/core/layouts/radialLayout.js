export const LAYOUT_ID = 'radial';
export const LAYOUT_LABEL = 'Radial';
export const LAYOUT_WORKSPACE = null;
export const LAYOUT_REQUIRES_FOCUS = true;

/**
 * BFS from focusNodeId, places nodes on concentric rings by hop count.
 * Ring 0 = focus node at center. Ring N = nodes N hops away.
 * Unreachable nodes placed in an extra outer ring.
 * Returns null if no nodes (force fallback). Auto-selects highest-degree node
 * when focusNodeId is absent or not found.
 */
export function computeStaticPositions(nodes, edges, { width, height }, options = {}) {
  if (!nodes.length) return {};

  const nodeMap = new Map(nodes.map(n => [n.id, n]));
  let focusId = options.focusNodeId;

  if (!focusId || !nodeMap.has(focusId)) {
    const autoFocus = [...nodes].sort((a, b) => (b.degree ?? 0) - (a.degree ?? 0))[0];
    if (!autoFocus) return null;
    focusId = autoFocus.id;
  }

  // Build undirected adjacency
  const adj = new Map(nodes.map(n => [n.id, []]));
  for (const e of edges) {
    const s = e.source?.id ?? e.source;
    const t = e.target?.id ?? e.target;
    if (adj.has(s) && adj.has(t)) {
      adj.get(s).push(t);
      adj.get(t).push(s);
    }
  }

  // BFS to assign hop count per node
  const hopOf = new Map();
  hopOf.set(focusId, 0);
  const queue = [focusId];
  while (queue.length) {
    const cur = queue.shift();
    const d = hopOf.get(cur);
    for (const nb of (adj.get(cur) ?? [])) {
      if (!hopOf.has(nb)) {
        hopOf.set(nb, d + 1);
        queue.push(nb);
      }
    }
  }

  // Group by ring index
  const rings = new Map(); // hop -> nodeId[]
  for (const [nid, hop] of hopOf) {
    if (!rings.has(hop)) rings.set(hop, []);
    rings.get(hop).push(nid);
  }

  // Disconnected nodes get their own outermost ring
  const disconnected = nodes.map(n => n.id).filter(id => !hopOf.has(id));
  const maxHop = rings.size > 0 ? Math.max(...rings.keys()) : 0;
  if (disconnected.length) rings.set(maxHop + 1, disconnected);

  const cx = width / 2;
  const cy = height / 2;
  const margin = 60;
  const maxR = Math.min(width, height) / 2 - margin;
  const numRings = rings.size; // includes ring 0
  const ringStep = numRings > 1 ? maxR / (numRings - 1) : maxR;

  const positions = {};
  for (const [hop, ids] of rings) {
    if (hop === 0) {
      positions[ids[0]] = { x: cx, y: cy };
      continue;
    }
    const r = Math.max(80, ringStep * hop);
    const n = ids.length;
    const sorted = [...ids].sort((a, b) => (nodeMap.get(b)?.degree ?? 0) - (nodeMap.get(a)?.degree ?? 0));
    for (let i = 0; i < n; i++) {
      const angle = -Math.PI / 2 + (2 * Math.PI * i) / n;
      positions[sorted[i]] = { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) };
    }
  }

  return positions;
}
