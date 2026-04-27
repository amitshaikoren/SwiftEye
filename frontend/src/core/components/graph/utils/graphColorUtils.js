// ── IP → number (for CIDR matching) ──────────────────────────────────────────
export function ipToNum(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function matchesCidr(ip, cidr) {
  if (!cidr || !ip) return false;
  cidr = cidr.trim();
  if (!cidr.includes('/')) return ip === cidr;
  const [network, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  if (isNaN(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (~((1 << (32 - bits)) - 1)) >>> 0;
  const ipNum  = ipToNum(ip);
  const netNum = ipToNum(network);
  if (ipNum === null || netNum === null) return false;
  return (ipNum & mask) === (netNum & mask);
}

// ── Resolve node fill/stroke from color mode ──────────────────────────────────
export function resolveNodeColor(node, mode, rules, pColors, nodePrivate, nodePrivateS, nodeExternal, nodeExternalS) {
  // Workspace-declared color (set by aggregator from schema.nodeTypes[type].color)
  // takes precedence over view-mode resolution. Mode-based coloring assumes
  // network-shaped data (is_private, os_guess, total_bytes, …) which other
  // workspaces don't carry.
  if (node.color) return [node.color + '22', node.color];
  switch (mode) {
    case 'os': {
      const os = node.os_guess || '';
      if (os.includes('Windows')) return ['#0d2137', '#388bfd'];
      if (os.includes('Linux') || os.includes('Unix')) return ['#0d2a1a', '#3fb950'];
      if (os.includes('macOS')) return ['#1c1c1c', '#8b949e'];
      if (os.includes('Network')) return ['#2a1a10', '#d29922'];
      return ['#1c1122', '#bc8cff'];
    }
    case 'protocol': {
      const proto = (node.protocol_set || [])[0];
      const c = proto ? (pColors[proto] || '#64748b') : '#64748b';
      return [c + '22', c];
    }
    case 'volume': {
      const b = node.total_bytes || 0;
      if (b >= 10_000_000) return ['#2a1010', '#f85149'];
      if (b >=  1_000_000) return ['#2a1a10', '#f0883e'];
      if (b >=    100_000) return ['#2a2010', '#d29922'];
      return ['#0d2a1a', '#3fb950'];
    }
    case 'custom': {
      const ips = node.ips || (node.id ? [node.id] : []);
      for (const rule of (rules || [])) {
        if (!rule.text || !rule.color) continue;
        if (ips.some(ip => matchesCidr(ip, rule.text))) {
          return [rule.color + '22', rule.color];
        }
      }
      // fallback to address mode
      return node.is_private ? [nodePrivate, nodePrivateS] : [nodeExternal, nodeExternalS];
    }
    default: // 'address'
      return node.is_private ? [nodePrivate, nodePrivateS] : [nodeExternal, nodeExternalS];
  }
}

// ── Resolve edge color from color mode ────────────────────────────────────────
export function resolveEdgeColor(edge, mode, rules, pColors) {
  // Workspace-declared edge color (set from schema.edgeTypes[type].color) wins.
  if (edge.color) return edge.color;
  switch (mode) {
    case 'volume': {
      const b = edge.total_bytes || 0;
      if (b >= 10_000_000) return '#f85149';
      if (b >=  1_000_000) return '#f0883e';
      if (b >=    100_000) return '#d29922';
      return '#3fb950';
    }
    case 'sessions': {
      const s = edge.session_count || 0;
      if (s >= 100) return '#f85149';
      if (s >=  21) return '#d29922';
      if (s >=   6) return '#3fb950';
      return '#388bfd';
    }
    case 'custom': {
      const proto = edge.protocol || '';
      for (const rule of (rules || [])) {
        if (!rule.text || !rule.color) continue;
        if (proto.toLowerCase().includes(rule.text.toLowerCase())) return rule.color;
      }
      return pColors[proto] || '#64748b';
    }
    default: // 'protocol'
      return pColors[edge.protocol] || '#64748b';
  }
}

// ── Winding-number point-in-polygon ──────────────────────────────────────────
export function inPolygon(px, py, pts) {
  let wn = 0;
  for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {
    const xi = pts[i].x, yi = pts[i].y, xj = pts[j].x, yj = pts[j].y;
    if (yj <= py) {
      if (yi > py && ((xi - xj) * (py - yj) - (px - xj) * (yi - yj)) > 0) wn++;
    } else {
      if (yi <= py && ((xi - xj) * (py - yj) - (px - xj) * (yi - yj)) < 0) wn--;
    }
  }
  return wn !== 0;
}
