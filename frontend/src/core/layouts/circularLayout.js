export const LAYOUT_ID = 'circular';
export const LAYOUT_LABEL = 'Circular';
export const LAYOUT_WORKSPACE = null;
export const LAYOUT_REQUIRES_FOCUS = false;

/**
 * Returns static {x, y} positions for all nodes arranged on concentric circles.
 * - ≤20 nodes: single ring
 * - 21–60 nodes: two concentric rings (inner = ~1/3, outer = rest)
 * - >60 nodes: returns null (fall back to force layout in useGraphSim)
 *
 * Angular ordering: highest-degree nodes first, starting at top (−π/2).
 */
export function computeStaticPositions(nodes, _edges, { width, height }) {
  if (!nodes.length) return {};
  if (nodes.length > 60) return null;

  const cx = width / 2;
  const cy = height / 2;
  const margin = 60;
  const maxR = Math.min(width, height) / 2 - margin;

  const sorted = [...nodes].sort((a, b) => (b.degree ?? 0) - (a.degree ?? 0));
  const positions = {};

  if (nodes.length <= 20) {
    const r = Math.max(maxR * 0.75, 80);
    placeOnRing(sorted, r, cx, cy, positions);
  } else {
    const splitIdx = Math.round(sorted.length / 3);
    const inner = sorted.slice(0, splitIdx);
    const outer = sorted.slice(splitIdx);
    placeOnRing(inner, maxR * 0.42, cx, cy, positions);
    placeOnRing(outer, maxR * 0.85, cx, cy, positions);
  }

  return positions;
}

function placeOnRing(nodes, r, cx, cy, out) {
  const n = nodes.length;
  for (let i = 0; i < n; i++) {
    const angle = -Math.PI / 2 + (2 * Math.PI * i) / n;
    out[nodes[i].id] = { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) };
  }
}
