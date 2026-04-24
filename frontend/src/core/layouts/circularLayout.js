export const LAYOUT_ID = 'circular';
export const LAYOUT_LABEL = 'Circular';
export const LAYOUT_WORKSPACE = null;
export const LAYOUT_REQUIRES_FOCUS = false;

/**
 * Degree-tiered circular layout with dashed ring guide lines.
 *
 * Nodes are sorted by degree descending and split into tiers:
 *   Ring 0 (innermost) — top ~15% by degree (hubs)
 *   Ring 1             — next ~35%
 *   Ring 2 (outermost) — remaining ~50% (leaf / peripheral)
 *
 * For small graphs (≤8 nodes) a single ring is used.
 * No node cap — scales by adjusting ring radii to fit node count.
 *
 * `ringGuides` in the returned value is consumed by GraphCanvas to draw
 * dashed SVG circles. Clicking a ring guide selects all nodes on that ring.
 */
export function computeStaticPositions(nodes, _edges, { width, height }) {
  if (!nodes.length) return {};

  const cx = width  / 2;
  const cy = height / 2;
  const margin = 60;
  const NODE_SPREAD = 36; // min arc spacing between nodes (px)

  const sorted = [...nodes].sort((a, b) => (b.degree ?? 0) - (a.degree ?? 0));
  const n = sorted.length;

  // ── Determine tier split indices ───────────────────────────────────
  let tiers;
  if (n <= 8) {
    tiers = [sorted];
  } else if (n <= 24) {
    const s0 = Math.max(1, Math.round(n * 0.25));
    tiers = [sorted.slice(0, s0), sorted.slice(s0)];
  } else {
    const s0 = Math.max(1, Math.round(n * 0.15));
    const s1 = Math.max(s0 + 1, Math.round(n * 0.50));
    tiers = [sorted.slice(0, s0), sorted.slice(s0, s1), sorted.slice(s1)];
  }

  // ── Compute ring radii driven by node count and available space ────
  const maxR = Math.min(width, height) / 2 - margin;
  const numRings = tiers.length;

  // Minimum radius for each ring so nodes aren't crowded
  const minRadii = tiers.map(tier =>
    tier.length <= 1 ? 0 : (tier.length * NODE_SPREAD) / (2 * Math.PI)
  );

  // Distribute rings evenly across maxR, but respect min radii
  // Inner ring starts at maxR * (1 / numRings), outer at maxR
  const radii = tiers.map((_, i) => {
    const fraction = numRings === 1 ? 1 : (i + 1) / numRings;
    return Math.max(minRadii[i], maxR * fraction);
  });

  // ── Place nodes on rings ───────────────────────────────────────────
  const positions = {};
  const ringMeta = []; // { r, nodeIds[] } — for guide lines + click-select

  for (let ti = 0; ti < tiers.length; ti++) {
    const tier = tiers[ti];
    const r = radii[ti];
    const nodeIds = [];
    for (let i = 0; i < tier.length; i++) {
      const angle = -Math.PI / 2 + (2 * Math.PI * i) / tier.length;
      positions[tier[i].id] = { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) };
      nodeIds.push(tier[i].id);
    }
    ringMeta.push({ r, nodeIds, label: RING_LABELS[ti] ?? `Ring ${ti + 1}` });
  }

  // Attach ring metadata so the renderer can draw guide circles and handle clicks
  positions.__ringGuides = ringMeta;
  return positions;
}

const RING_LABELS = ['Hubs', 'Mid-tier', 'Peripheral'];
