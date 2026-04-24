export const LAYOUT_ID = 'circular';
export const LAYOUT_LABEL = 'Circular';
export const LAYOUT_WORKSPACE = null;
export const LAYOUT_REQUIRES_FOCUS = false;

/**
 * Per-component circular layout.
 *
 * Each connected component gets its own circle. Components are arranged
 * across the canvas (largest at center, others in a surrounding ring).
 * Within each component, nodes are sorted by degree descending.
 *
 * `__ringGuides` is attached to the returned position map so the renderer
 * can draw a dashed guide circle for each component. Clicking within ±10px
 * of a guide ring selects all nodes in that component.
 */
export function computeStaticPositions(nodes, edges, { width, height }) {
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

  // ── 2. Find connected components ───────────────────────────────────
  const visited = new Set();
  const components = [];
  for (const n of nodes) {
    if (visited.has(n.id)) continue;
    const comp = [];
    const q = [n.id];
    visited.add(n.id);
    while (q.length) {
      const cur = q.shift();
      comp.push(cur);
      for (const nb of adj.get(cur) ?? []) {
        if (!visited.has(nb)) { visited.add(nb); q.push(nb); }
      }
    }
    components.push(comp);
  }

  // Sort: largest component first
  components.sort((a, b) => b.length - a.length);

  // ── 3. Compute per-component circle radius ─────────────────────────
  const NODE_SPREAD = 36; // min arc spacing between nodes
  const COMP_PADDING = 48; // gap between component bubbles

  const compData = components.map(comp => {
    const sorted = [...comp].sort((a, b) =>
      (nodeMap.get(b)?.degree ?? 0) - (nodeMap.get(a)?.degree ?? 0)
    );
    const r = comp.length <= 1
      ? 0
      : Math.max(60, (comp.length * NODE_SPREAD) / (2 * Math.PI));
    return { ids: sorted, r };
  });

  // ── 4. Arrange component bubbles on canvas ─────────────────────────
  const cx = width  / 2;
  const cy = height / 2;

  // Primary (largest) at canvas center. Satellites in orbit ring.
  const primary = compData[0];
  const rest     = compData.slice(1);

  const maxSatR  = rest.length ? Math.max(...rest.map(c => c.r)) : 0;
  const orbitR   = primary.r + maxSatR + COMP_PADDING * 2;

  // Assign a canvas center per component
  const centers = [{ x: cx, y: cy }];
  for (let i = 0; i < rest.length; i++) {
    const angle = -Math.PI / 2 + (2 * Math.PI * i) / rest.length;
    centers.push({ x: cx + orbitR * Math.cos(angle), y: cy + orbitR * Math.sin(angle) });
  }

  // ── 5. Place nodes + build ring guide metadata ─────────────────────
  const positions = {};
  const ringGuides = [];

  for (let ci = 0; ci < compData.length; ci++) {
    const { ids, r } = compData[ci];
    const { x: ccx, y: ccy } = centers[ci];

    if (ids.length === 1) {
      positions[ids[0]] = { x: ccx, y: ccy };
    } else {
      for (let i = 0; i < ids.length; i++) {
        const angle = -Math.PI / 2 + (2 * Math.PI * i) / ids.length;
        positions[ids[i]] = { x: ccx + r * Math.cos(angle), y: ccy + r * Math.sin(angle) };
      }
    }

    if (r > 0) {
      ringGuides.push({ cx: ccx, cy: ccy, r, nodeIds: ids });
    }
  }

  positions.__ringGuides = ringGuides;
  return positions;
}
