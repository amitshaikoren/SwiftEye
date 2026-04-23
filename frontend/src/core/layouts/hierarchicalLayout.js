import dagre from 'dagre';

export const LAYOUT_ID = 'hierarchical';
export const LAYOUT_LABEL = 'Hierarchical';
export const LAYOUT_WORKSPACE = null;
export const LAYOUT_REQUIRES_FOCUS = true;

const NODE_W = 60;
const NODE_H = 40;

/**
 * Dagre top-down layout. Nodes placed in rank layers; edges determine parent→child.
 * focusNodeId is used as a hint for auto-root selection but dagre ignores it structurally
 * (edge direction determines rank). Auto-selects highest-in-degree node as root when
 * no focusNodeId is provided or it is not found.
 * Returns null on dagre failure (useGraphSim falls back to force).
 */
export function computeStaticPositions(nodes, edges, { width, height }, options = {}) {
  if (!nodes.length) return {};

  const nodeSet = new Set(nodes.map(n => n.id));

  // Auto-select root: highest in-degree, tie-break by total degree
  let rootId = options.focusNodeId;
  if (!rootId || !nodeSet.has(rootId)) {
    const inDeg = new Map(nodes.map(n => [n.id, 0]));
    for (const e of edges) {
      const t = e.target?.id ?? e.target;
      if (inDeg.has(t)) inDeg.set(t, inDeg.get(t) + 1);
    }
    rootId = [...nodes].sort((a, b) => {
      const d = (inDeg.get(b.id) ?? 0) - (inDeg.get(a.id) ?? 0);
      return d !== 0 ? d : (b.degree ?? 0) - (a.degree ?? 0);
    })[0]?.id;
    if (!rootId) return null;
  }

  const g = new dagre.graphlib.Graph({ multigraph: false });
  g.setGraph({ rankdir: 'TB', nodesep: 80, ranksep: 100, marginx: 20, marginy: 20 });
  g.setDefaultEdgeLabel(() => ({}));

  for (const n of nodes) g.setNode(n.id, { width: NODE_W, height: NODE_H });

  for (const e of edges) {
    const s = e.source?.id ?? e.source;
    const t = e.target?.id ?? e.target;
    if (nodeSet.has(s) && nodeSet.has(t) && s !== t) {
      try { g.setEdge(s, t); } catch (_) {}
    }
  }

  try { dagre.layout(g); } catch (_) { return null; }

  // Collect dagre positions
  const raw = {};
  for (const id of g.nodes()) {
    const n = g.node(id);
    if (n?.x != null) raw[id] = { x: n.x, y: n.y };
  }
  if (!Object.keys(raw).length) return null;

  // Scale to fit canvas
  const margin = 60;
  const xs = Object.values(raw).map(p => p.x);
  const ys = Object.values(raw).map(p => p.y);
  const minX = Math.min(...xs), maxX = Math.max(...xs);
  const minY = Math.min(...ys), maxY = Math.max(...ys);
  const rangeX = maxX - minX || 1;
  const rangeY = maxY - minY || 1;
  const availW = width - margin * 2;
  const availH = height - margin * 2;
  const scale = Math.min(availW / rangeX, availH / rangeY, 2.5);
  const offX = margin + (availW - rangeX * scale) / 2;
  const offY = margin;

  const positions = {};
  for (const [id, p] of Object.entries(raw)) {
    positions[id] = {
      x: offX + (p.x - minX) * scale,
      y: offY + (p.y - minY) * scale,
    };
  }
  return positions;
}
