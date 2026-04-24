export const LAYOUT_ID = 'radial';
export const LAYOUT_LABEL = 'Radial';
export const LAYOUT_WORKSPACE = null;
export const LAYOUT_REQUIRES_FOCUS = true;

/**
 * Multi-focal radial layout.
 *
 * Finds connected components, runs a BFS-ring layout per component, then
 * arranges the resulting "bubbles" across the canvas. The component containing
 * focusNodeId (or the largest component when absent) is placed at canvas center;
 * remaining components are arranged in a ring around it.
 *
 * Within each component the BFS root is:
 *   - focusNodeId  (if it belongs to that component)
 *   - else the highest-degree node in the component
 *
 * Returns a { [nodeId]: { x, y } } position map.
 */
export function computeStaticPositions(nodes, edges, { width, height }, options = {}) {
  if (!nodes.length) return {};

  const nodeMap = new Map(nodes.map(n => [n.id, n]));

  // ── 1. Build undirected adjacency ──────────────────────────────────
  const adj = new Map(nodes.map(n => [n.id, []]));
  for (const e of edges) {
    const s = e.source?.id ?? e.source;
    const t = e.target?.id ?? e.target;
    if (adj.has(s) && adj.has(t)) {
      adj.get(s).push(t);
      adj.get(t).push(s);
    }
  }

  // ── 2. Find connected components (BFS) ────────────────────────────
  const visited = new Set();
  const components = []; // component = nodeId[]

  for (const n of nodes) {
    if (visited.has(n.id)) continue;
    const comp = [];
    const q = [n.id];
    visited.add(n.id);
    while (q.length) {
      const cur = q.shift();
      comp.push(cur);
      for (const nb of adj.get(cur) ?? []) {
        if (!visited.has(nb)) {
          visited.add(nb);
          q.push(nb);
        }
      }
    }
    components.push(comp);
  }

  // ── 3. Determine focus component and order ─────────────────────────
  const focusId = options.focusNodeId && nodeMap.has(options.focusNodeId)
    ? options.focusNodeId
    : null;

  // Sort: focus component first, then by descending size
  components.sort((a, b) => {
    const aHasFocus = focusId && a.includes(focusId) ? 1 : 0;
    const bHasFocus = focusId && b.includes(focusId) ? 1 : 0;
    if (aHasFocus !== bHasFocus) return bHasFocus - aHasFocus;
    return b.length - a.length;
  });

  // ── 4. Per-component BFS ring layout (local coords) ────────────────
  const RING_SPACING   = 90;  // px between rings
  const MIN_RING_R     = 70;  // minimum first-ring radius
  const NODE_SPREAD    = 38;  // min arc spacing between nodes on a ring
  const BUBBLE_PADDING = 50;  // extra margin between bubbles

  const compLayouts = components.map((comp, ci) => {
    // Pick root: focus node if in this component, else highest-degree
    let rootId = focusId && comp.includes(focusId) ? focusId : null;
    if (!rootId) {
      rootId = comp.reduce((best, id) =>
        (nodeMap.get(id)?.degree ?? 0) > (nodeMap.get(best)?.degree ?? 0) ? id : best
      , comp[0]);
    }

    // BFS to assign hop count
    const hopOf = new Map();
    hopOf.set(rootId, 0);
    const q = [rootId];
    while (q.length) {
      const cur = q.shift();
      const d = hopOf.get(cur);
      for (const nb of adj.get(cur) ?? []) {
        if (!hopOf.has(nb)) { hopOf.set(nb, d + 1); q.push(nb); }
      }
    }

    // Group by ring
    const rings = new Map();
    for (const [id, hop] of hopOf) {
      if (!rings.has(hop)) rings.set(hop, []);
      rings.get(hop).push(id);
    }

    // Determine ring radii — radius for ring k is driven by how many nodes
    // need to fit on that ring with at least NODE_SPREAD arc spacing
    const ringRadii = new Map();
    ringRadii.set(0, 0);
    for (const [hop, ids] of rings) {
      if (hop === 0) continue;
      const minBySpacing = (ids.length * NODE_SPREAD) / (2 * Math.PI);
      const minByStep    = Math.max(MIN_RING_R, hop * RING_SPACING);
      ringRadii.set(hop, Math.max(minBySpacing, minByStep));
    }

    // Bubble radius = outermost ring radius + some padding
    const maxRingR = rings.size > 1 ? Math.max(...[...ringRadii.values()]) : 0;
    const bubbleR  = maxRingR + BUBBLE_PADDING;

    // Compute local positions (centered at 0,0)
    const localPos = {};
    for (const [hop, ids] of rings) {
      if (hop === 0) { localPos[ids[0]] = { x: 0, y: 0 }; continue; }
      const r = ringRadii.get(hop);
      const sorted = [...ids].sort((a, b) =>
        (nodeMap.get(b)?.degree ?? 0) - (nodeMap.get(a)?.degree ?? 0)
      );
      for (let i = 0; i < sorted.length; i++) {
        const angle = -Math.PI / 2 + (2 * Math.PI * i) / sorted.length;
        localPos[sorted[i]] = { x: r * Math.cos(angle), y: r * Math.sin(angle) };
      }
    }

    return { comp, rootId, localPos, bubbleR };
  });

  // ── 5. Arrange bubbles on canvas ──────────────────────────────────
  // Primary (index 0) goes at canvas center.
  // Remaining bubbles are placed in a ring around the primary.
  const cx = width  / 2;
  const cy = height / 2;

  const positions = {};
  const primary = compLayouts[0];

  // Translate primary to canvas center
  for (const [id, p] of Object.entries(primary.localPos)) {
    positions[id] = { x: cx + p.x, y: cy + p.y };
  }

  const rest = compLayouts.slice(1);
  if (rest.length === 0) return positions;

  // Orbit radius: primary bubble radius + gap + max satellite bubble radius
  const maxSatR  = Math.max(...rest.map(c => c.bubbleR));
  const orbitR   = primary.bubbleR + maxSatR + BUBBLE_PADDING;

  for (let i = 0; i < rest.length; i++) {
    const angle    = -Math.PI / 2 + (2 * Math.PI * i) / rest.length;
    const satCx    = cx + orbitR * Math.cos(angle);
    const satCy    = cy + orbitR * Math.sin(angle);
    for (const [id, p] of Object.entries(rest[i].localPos)) {
      positions[id] = { x: satCx + p.x, y: satCy + p.y };
    }
  }

  return positions;
}
