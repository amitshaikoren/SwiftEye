import * as d3 from 'd3';

// ── Shape drawing ─────────────────────────────────────────────────────────────

/**
 * Draws the complete node shape (path + fill + stroke) for any node type.
 * Single canonical replacement for scattered if/else shape branching.
 *
 * @param {CanvasRenderingContext2D} ctx
 * @param {object} node  - graph node with x, y, r plus type flags
 * @param {object} opts
 *   r             - pre-computed node radius
 *   t             - d3 zoom transform { k }
 *   isSel / isH   - selection / hover state
 *   acColor       - accent color hex
 *   acGColor      - accent glow color
 *   nodeSubnet / nodeSubnetS / nodeGateway / nodeGatewayS - theme colors
 *   CLUSTER_COLORS - array of hex colors for cluster nodes
 *   colorOverride  - { fill, stroke } | null  (from AnnotationStore color_override)
 *   resolveColor   - fn(node) => [fill, stroke]  (from graphColorUtils)
 */
export function drawShapePath(ctx, node, opts) {
  const {
    r, t, isSel, isH, acColor, acGColor,
    nodeSubnet, nodeSubnetS, nodeGateway, nodeGatewayS,
    CLUSTER_COLORS, colorOverride, resolveColor,
  } = opts;

  const isGateway = node.plugin_data?.network_role?.role === 'gateway';

  if (node.is_cluster) {
    const cc = CLUSTER_COLORS[(node.cluster_id || 0) % CLUSTER_COLORS.length];
    const hr = r * 1.8;
    ctx.beginPath();
    for (let i = 0; i < 6; i++) {
      const angle = (Math.PI / 3) * i - Math.PI / 6;
      const hx = node.x + hr * Math.cos(angle);
      const hy = node.y + hr * Math.sin(angle);
      if (i === 0) ctx.moveTo(hx, hy); else ctx.lineTo(hx, hy);
    }
    ctx.closePath();
    ctx.fillStyle = isSel ? cc + '44' : cc + '18';
    ctx.fill();
    ctx.strokeStyle = isSel ? '#fff' : isH ? acGColor : cc;
    ctx.lineWidth = isSel || isH ? 2.5 : 2;
    ctx.stroke();
    if (node.member_count && t.k > 0.3) {
      ctx.font = `bold ${Math.max(9, 11 / t.k)}px JetBrains Mono, monospace`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = cc;
      ctx.fillText(String(node.member_count), node.x, node.y);
    }

  } else if (node.is_subnet) {
    const s = r * 2.0;
    const rad = 4;
    ctx.beginPath();
    if (ctx.roundRect) {
      ctx.roundRect(node.x - s / 2, node.y - s / 2, s, s, rad);
    } else {
      ctx.rect(node.x - s / 2, node.y - s / 2, s, s);
    }
    ctx.fillStyle = isSel ? acColor + '33' : nodeSubnet;
    ctx.fill();
    ctx.strokeStyle = isSel ? acColor : isH ? acGColor : nodeSubnetS;
    ctx.lineWidth = isSel ? 2.5 : 1.5;
    ctx.setLineDash([4, 2]);
    ctx.stroke();
    ctx.setLineDash([]);
    const memberCount = node.ips?.length || node.member_count;
    if (memberCount && t.k > 0.3) {
      ctx.font = `bold ${Math.max(8, 10 / t.k)}px JetBrains Mono, monospace`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = nodeSubnetS;
      ctx.fillText(String(memberCount), node.x, node.y);
    }

  } else if (isGateway) {
    const s = r * 1.6;
    ctx.save();
    ctx.translate(node.x, node.y);
    ctx.rotate(Math.PI / 4);
    ctx.beginPath();
    ctx.rect(-s / 2, -s / 2, s, s);
    ctx.fillStyle = isSel ? acColor + '33' : nodeGateway;
    ctx.fill();
    ctx.strokeStyle = isSel ? acColor : isH ? acGColor : nodeGatewayS;
    ctx.lineWidth = isSel || isH ? 2.5 : 1.8;
    ctx.stroke();
    ctx.restore();

  } else {
    ctx.beginPath();
    ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
    if (node.synthetic) {
      const nc = node.color || '#f0883e';
      ctx.fillStyle = isSel ? nc + '55' : nc + '22';
      ctx.fill();
      ctx.strokeStyle = isSel ? '#fff' : isH ? '#fff' : nc;
      ctx.lineWidth = isSel || isH ? 2.5 : 2;
      ctx.setLineDash([4, 3]);
      ctx.stroke();
      ctx.setLineDash([]);
    } else {
      let [nFill, nStroke] = resolveColor(node);
      if (isSel) {
        ctx.fillStyle = acColor + '33';
      } else if (colorOverride) {
        // Radial gradient: darker centre fading to edge, same hue as override colour
        const grad = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, r);
        grad.addColorStop(0, colorOverride.stroke + 'cc');
        grad.addColorStop(1, colorOverride.stroke + '44');
        ctx.fillStyle = grad;
        nStroke = colorOverride.stroke;
      } else {
        ctx.fillStyle = nFill;
      }
      ctx.fill();
      ctx.strokeStyle = isSel ? acColor : isH ? acGColor : nStroke;
      ctx.lineWidth = isSel || isH ? 2.5 : (colorOverride ? 2.5 : 1.5);
      ctx.stroke();
    }
  }
}

// ── Color override ─────────────────────────────────────────────────────────────

/**
 * Returns { fill, stroke } for a color_override annotation, or null.
 * fill/stroke are pre-baked hex strings (with alpha where applicable).
 */
export function applyColorOverride(override) {
  if (!override) return null;
  return { fill: override.fill, stroke: override.stroke };
}

// ── Convex hull geometry ───────────────────────────────────────────────────────

/**
 * Computes a smooth convex hull path around a set of 2D positions.
 * Returns a Path2D or null.
 * Fallbacks: 1 point → circle, 2 points or collinear → capsule.
 *
 * @param {Array<[number,number]>} positions
 * @param {number} pad  expansion radius in graph units (default 30)
 */
export function computeConvexHull(positions, pad = 30) {
  if (!positions || positions.length === 0) return null;

  if (positions.length === 1) {
    const [p] = positions;
    const path = new Path2D();
    path.arc(p[0], p[1], pad, 0, Math.PI * 2);
    return path;
  }

  if (positions.length === 2) {
    return _capsulePath(positions[0], positions[1], pad);
  }

  const hull = d3.polygonHull(positions);
  if (!hull) {
    return _capsulePath(positions[0], positions[positions.length - 1], pad);
  }

  // Expand each hull vertex outward from the centroid
  const cx = hull.reduce((s, p) => s + p[0], 0) / hull.length;
  const cy = hull.reduce((s, p) => s + p[1], 0) / hull.length;
  const expanded = hull.map(([x, y]) => {
    const dx = x - cx, dy = y - cy;
    const dist = Math.sqrt(dx * dx + dy * dy) || 1;
    return [x + (dx / dist) * pad, y + (dy / dist) * pad];
  });

  // Smooth curve through expanded vertices using midpoint quadratic Bézier
  const n = expanded.length;
  const path = new Path2D();
  for (let i = 0; i < n; i++) {
    const a = expanded[i];
    const b = expanded[(i + 1) % n];
    const c = expanded[(i + 2) % n];
    const mx1 = (a[0] + b[0]) / 2, my1 = (a[1] + b[1]) / 2;
    const mx2 = (b[0] + c[0]) / 2, my2 = (b[1] + c[1]) / 2;
    if (i === 0) path.moveTo(mx1, my1);
    path.quadraticCurveTo(b[0], b[1], mx2, my2);
  }
  path.closePath();
  return path;
}

function _capsulePath(a, b, pad) {
  const dx = b[0] - a[0], dy = b[1] - a[1];
  const angle = Math.atan2(dy, dx);
  const path = new Path2D();
  path.arc(a[0], a[1], pad, angle + Math.PI / 2, angle - Math.PI / 2, false);
  path.arc(b[0], b[1], pad, angle - Math.PI / 2, angle + Math.PI / 2, false);
  path.closePath();
  return path;
}

// ── Hulls ─────────────────────────────────────────────────────────────────────

/**
 * Draws all hull annotations. Called before edges + nodes (z-order 1).
 * ctx must already be in the d3-transformed coordinate space.
 *
 * @param {CanvasRenderingContext2D} ctx
 * @param {object} transform  d3 zoom transform { k, x, y }
 * @param {Array}  hulls      [{ name, members, color, label, cohesion }]
 * @param {Map}    nodeMap    Map<nodeId, { x, y }>
 */
export function drawHulls(ctx, transform, hulls, nodeMap) {
  if (!hulls || hulls.length === 0) return;
  const tk = transform.k;

  for (const hull of hulls) {
    if (!hull.members?.length) continue;
    const positions = hull.members
      .map(id => nodeMap.get(id))
      .filter(Boolean)
      .map(n => [n.x, n.y]);
    if (!positions.length) continue;

    const path = computeConvexHull(positions, 30);
    if (!path) continue;

    ctx.save();
    ctx.globalAlpha = 0.10;
    ctx.fillStyle = hull.color;
    ctx.fill(path);

    ctx.globalAlpha = 0.55;
    ctx.strokeStyle = hull.color;
    ctx.lineWidth = 1.5 / tk;
    ctx.setLineDash([6 / tk, 4 / tk]);
    ctx.stroke(path);
    ctx.setLineDash([]);

    if (tk > 0.3) {
      const label = hull.label || hull.name;
      const minX = Math.min(...positions.map(p => p[0])) - 30;
      const minY = Math.min(...positions.map(p => p[1])) - 30;
      ctx.globalAlpha = 0.75;
      ctx.font = `bold ${Math.max(9, 11 / tk)}px JetBrains Mono, monospace`;
      ctx.textAlign = 'left';
      ctx.textBaseline = 'top';
      ctx.fillStyle = hull.color;
      ctx.fillText(label, minX + 5, minY + 4);
    }
    ctx.restore();
  }
}

// ── Rings ─────────────────────────────────────────────────────────────────────

/**
 * Draws ring annotations around nodes (z-order 4, after node shapes).
 * ctx must already be in the d3-transformed coordinate space.
 *
 * @param {CanvasRenderingContext2D} ctx
 * @param {object} transform
 * @param {object} nodeRings   { nodeId: [{ color, style, width }] }
 * @param {Map}    nodeMap     Map<nodeId, { x, y }>
 * @param {Map}    radiusMap   Map<nodeId, number>
 */
export function drawRings(ctx, transform, nodeRings, nodeMap, radiusMap) {
  if (!nodeRings) return;
  const tk = transform.k;

  for (const [nodeId, ringList] of Object.entries(nodeRings)) {
    const pos = nodeMap.get(nodeId);
    const r = radiusMap.get(nodeId);
    if (!pos || r == null) continue;

    for (const ring of ringList) {
      const rw = ring.width ?? 2;
      ctx.save();
      ctx.globalAlpha = 0.9;

      if (ring.style === 'glow') {
        const ggl = ctx.createRadialGradient(pos.x, pos.y, r, pos.x, pos.y, r * 2.5);
        ggl.addColorStop(0, ring.color + '40');
        ggl.addColorStop(1, 'transparent');
        ctx.fillStyle = ggl;
        ctx.fillRect(pos.x - r * 2.5, pos.y - r * 2.5, r * 5, r * 5);
      }

      ctx.beginPath();
      ctx.arc(pos.x, pos.y, r + 4, 0, Math.PI * 2);
      ctx.strokeStyle = ring.color;
      ctx.lineWidth = rw / tk;
      if (ring.style === 'dashed') ctx.setLineDash([6 / tk, 4 / tk]);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.restore();
    }
  }
}

// ── Badges ────────────────────────────────────────────────────────────────────

/**
 * Draws badge pills below a node's label (z-order 6, topmost).
 * Shows up to 2 badges; collapses rest to "+N more". Zoom-guarded at k > 0.45.
 * ctx must already be in the d3-transformed coordinate space.
 *
 * @param {CanvasRenderingContext2D} ctx
 * @param {object} transform
 * @param {object} node       node with .x .y
 * @param {number} r          node radius
 * @param {Array}  badges     [{ text, color }]  (from RenderSnapshot.badges[nodeId])
 */
export function drawBadges(ctx, transform, node, r, badges) {
  if (!badges || !badges.length) return;
  if (transform.k <= 0.45) return;

  const tk = transform.k;
  const fs = Math.max(7, 8 / tk);
  ctx.font = `600 ${fs}px JetBrains Mono, monospace`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';

  const displayBadges = badges.length <= 2
    ? badges
    : [badges[0], { text: `+${badges.length - 1} more`, color: badges[0].color }];

  // Position below the node label (~fs + 4 label height + 6px gap)
  const labelH = Math.max(8, 10 / tk) + 4;
  let offsetY = node.y + r + 5 + labelH + 4;

  for (const badge of displayBadges) {
    const tw = ctx.measureText(badge.text).width;
    const pad = 3;
    const bx = node.x - tw / 2 - pad;
    const bw = tw + pad * 2;
    const bh = fs + 4;
    const br = 3;

    ctx.fillStyle = badge.color;
    ctx.beginPath();
    ctx.moveTo(bx + br, offsetY);
    ctx.lineTo(bx + bw - br, offsetY); ctx.arcTo(bx + bw, offsetY, bx + bw, offsetY + br, br);
    ctx.lineTo(bx + bw, offsetY + bh - br); ctx.arcTo(bx + bw, offsetY + bh, bx + bw - br, offsetY + bh, br);
    ctx.lineTo(bx + br, offsetY + bh); ctx.arcTo(bx, offsetY + bh, bx, offsetY + bh - br, br);
    ctx.lineTo(bx, offsetY + br); ctx.arcTo(bx, offsetY, bx + br, offsetY, br);
    ctx.closePath();
    ctx.fill();

    ctx.fillStyle = _badgeTextColor(badge.color);
    ctx.fillText(badge.text, node.x, offsetY + 2);

    offsetY += bh + 2;
  }
}

function _badgeTextColor(bgHex) {
  try {
    const r = parseInt(bgHex.slice(1, 3), 16);
    const g = parseInt(bgHex.slice(3, 5), 16);
    const b = parseInt(bgHex.slice(5, 7), 16);
    return (0.299 * r + 0.587 * g + 0.114 * b) > 128 ? 'rgba(0,0,0,0.85)' : '#e2ccff';
  } catch { return '#e2ccff'; }
}
