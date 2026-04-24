import * as d3 from 'd3';

export const LAYOUT_ID = 'force';
export const LAYOUT_LABEL = 'Force';
export const LAYOUT_WORKSPACE = null;
export const LAYOUT_REQUIRES_FOCUS = false;

/**
 * Builds and returns a configured d3 force simulation.
 * Extracted from useGraphSim so graph-layouts.md can swap layout modes here.
 *
 * @param {object[]} nodes       - D3-mutated node objects (have .x .y after simulation)
 * @param {object[]} edges       - edge objects with .source / .target
 * @param {object}   dimensions  - { width, height }
 * @param {Function} getRadius   - fn(node) => number  (gRRef.current)
 * @param {object}   options     - { hullCohesion, forceParams }
 */
export function buildForceSimulation(nodes, edges, { width, height }, getRadius, options = {}) {
  const hasAnyClusters = nodes.some(n => n.is_cluster);
  const nodeCount = nodes.length;
  const chargeDistMax = hasAnyClusters ? 700
    : nodeCount > 200 ? 800
    : nodeCount > 50  ? 600
    : 500;

  const baseCharge    = options.forceParams?.chargeStrength  ?? -180;
  const linkDist      = options.forceParams?.linkDistance     ?? 130;
  const alphaDecayVal = options.forceParams?.alphaDecay       ?? 0.025;
  const velDecayVal   = options.forceParams?.velocityDecay    ?? 0.4;

  const sim = d3.forceSimulation(nodes)
    .force('charge', d3.forceManyBody()
      .strength(d => d.is_cluster ? -350 - (d.member_count || 0) * 18 : baseCharge)
      .distanceMax(chargeDistMax))
    .force('link', d3.forceLink(edges).id(d => d.id)
      .distance(d => {
        const s = typeof d.source === 'object' ? d.source : null;
        const t = typeof d.target === 'object' ? d.target : null;
        if (s?.is_cluster || t?.is_cluster) return 200;
        return linkDist;
      })
      .strength(0.5))
    .force('center', d3.forceCenter(width / 2, height / 2).strength(0.05))
    .force('collision', d3.forceCollide().radius(d =>
      d.is_cluster ? getRadius(d) * 1.8 + 15 : getRadius(d) + 8))
    .force('x', d3.forceX(width / 2).strength(0.02))
    .force('y', d3.forceY(height / 2).strength(0.02))
    .alphaDecay(alphaDecayVal)
    .velocityDecay(velDecayVal)
    .on('end', () => {
      sim.force('charge').strength(
        d => d.is_cluster ? -70 - (d.member_count || 0) * 4 : -45
      );
    });

  // Hull cohesion forces — pull members toward their hull centroid each tick.
  // Default cohesion is 0 for all hulls so this is a no-op until explicitly enabled.
  for (let i = 0; i < (options.hullCohesion || []).length; i++) {
    const { members, strength } = options.hullCohesion[i];
    const memberSet = new Set(members);
    const getCentroid = (axis) => {
      const inSim = nodes.filter(n => memberSet.has(n.id));
      if (!inSim.length) return 0;
      return inSim.reduce((s, n) => s + (n[axis] || 0), 0) / inSim.length;
    };
    sim
      .force(`hull_cx_${i}`, d3.forceX()
        .x(() => getCentroid('x'))
        .strength(d => memberSet.has(d.id) ? strength * 0.08 : 0))
      .force(`hull_cy_${i}`, d3.forceY()
        .y(() => getCentroid('y'))
        .strength(d => memberSet.has(d.id) ? strength * 0.08 : 0));
  }

  return sim;
}
