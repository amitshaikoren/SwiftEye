// Shared legend data used by GraphOptionsPanel (sidebar) and GraphLegend (canvas overlay).
// Items with a `filter` field support legend-as-filter toggling in the recipe.

export const NODE_LEGENDS = {
  address: [
    { dot: true,  fill: 'var(--node-private)',  stroke: 'var(--node-private-s)',  label: 'Private (RFC1918)',
      filter: { target: 'nodes', conditions: [{ field: 'is_private', op: '=', value: true }] } },
    { dot: true,  fill: 'var(--node-external)', stroke: 'var(--node-external-s)', label: 'External',
      filter: { target: 'nodes', conditions: [{ field: 'is_private', op: '=', value: false }, { field: 'is_gateway', op: '=', value: false }], logic: 'and' } },
    { dot: true,  fill: 'var(--node-gateway)',  stroke: 'var(--node-gateway-s)',  label: 'Gateway',
      filter: { target: 'nodes', conditions: [{ field: 'is_gateway', op: '=', value: true }] } },
    { dot: true,  fill: 'var(--node-subnet)',   stroke: 'var(--node-subnet-s)',   label: 'Subnet node' },
  ],
  os: [
    { dot: true, fill: '#0d2137', stroke: '#388bfd', label: 'Windows',
      filter: { target: 'nodes', conditions: [{ field: 'os_guess', op: 'matches', value: 'Windows' }] } },
    { dot: true, fill: '#0d2a1a', stroke: '#3fb950', label: 'Linux / Unix',
      filter: { target: 'nodes', conditions: [{ field: 'os_guess', op: 'matches', value: 'Linux|Unix' }] } },
    { dot: true, fill: '#1c1c1c', stroke: '#8b949e', label: 'macOS',
      filter: { target: 'nodes', conditions: [{ field: 'os_guess', op: 'matches', value: 'macOS' }] } },
    { dot: true, fill: '#2a1a10', stroke: '#d29922', label: 'Network device',
      filter: { target: 'nodes', conditions: [{ field: 'os_guess', op: 'matches', value: 'Network' }] } },
    { dot: true, fill: '#1c1122', stroke: '#bc8cff', label: 'Unknown' },
  ],
  protocol: [
    { dot: true, fill: '#0d1f3a', stroke: '#1f6feb', label: 'TCP dominant' },
    { dot: true, fill: '#061520', stroke: '#388bfd', label: 'TLS dominant' },
    { dot: true, fill: '#0d2a1a', stroke: '#3fb950', label: 'DNS dominant' },
    { dot: true, fill: '#2a1e0d', stroke: '#d29922', label: 'HTTP dominant' },
  ],
  volume: [
    { dot: true, fill: '#0d2a1a', stroke: '#3fb950', label: 'Low  (< 100 KB)',
      filter: { target: 'nodes', conditions: [{ field: 'total_bytes', op: '<', value: 100000 }] } },
    { dot: true, fill: '#2a2010', stroke: '#d29922', label: 'Medium  (< 1 MB)',
      filter: { target: 'nodes', conditions: [{ field: 'total_bytes', op: '>=', value: 100000 }, { field: 'total_bytes', op: '<', value: 1000000 }], logic: 'and' } },
    { dot: true, fill: '#2a1a10', stroke: '#f0883e', label: 'High  (< 10 MB)',
      filter: { target: 'nodes', conditions: [{ field: 'total_bytes', op: '>=', value: 1000000 }, { field: 'total_bytes', op: '<', value: 10000000 }], logic: 'and' } },
    { dot: true, fill: '#2a1010', stroke: '#f85149', label: 'Very high  (≥ 10 MB)',
      filter: { target: 'nodes', conditions: [{ field: 'total_bytes', op: '>=', value: 10000000 }] } },
  ],
};

export const EDGE_LEGENDS = {
  protocol: [
    { dot: false, fill: '#1f6feb', label: 'TCP',
      filter: { target: 'edges', conditions: [{ field: 'protocol', op: '=', value: 'TCP' }] } },
    { dot: false, fill: '#388bfd', label: 'TLS',
      filter: { target: 'edges', conditions: [{ field: 'protocol', op: '=', value: 'TLS' }] } },
    { dot: false, fill: '#3fb950', label: 'DNS',
      filter: { target: 'edges', conditions: [{ field: 'protocol', op: '=', value: 'DNS' }] } },
    { dot: false, fill: '#d29922', label: 'HTTP',
      filter: { target: 'edges', conditions: [{ field: 'protocol', op: '=', value: 'HTTP' }] } },
  ],
  volume: [
    { dot: false, fill: '#3fb950', label: 'Low  (< 100 KB)',
      filter: { target: 'edges', conditions: [{ field: 'total_bytes', op: '<', value: 100000 }] } },
    { dot: false, fill: '#d29922', label: 'Medium  (< 1 MB)',
      filter: { target: 'edges', conditions: [{ field: 'total_bytes', op: '>=', value: 100000 }, { field: 'total_bytes', op: '<', value: 1000000 }], logic: 'and' } },
    { dot: false, fill: '#f0883e', label: 'High  (< 10 MB)',
      filter: { target: 'edges', conditions: [{ field: 'total_bytes', op: '>=', value: 1000000 }, { field: 'total_bytes', op: '<', value: 10000000 }], logic: 'and' } },
    { dot: false, fill: '#f85149', label: 'Very high  (≥ 10 MB)',
      filter: { target: 'edges', conditions: [{ field: 'total_bytes', op: '>=', value: 10000000 }] } },
  ],
  sessions: [
    { dot: false, fill: '#388bfd', label: '1–5 sessions',
      filter: { target: 'edges', conditions: [{ field: 'session_count', op: '>=', value: 1 }, { field: 'session_count', op: '<=', value: 5 }], logic: 'and' } },
    { dot: false, fill: '#3fb950', label: '6–20 sessions',
      filter: { target: 'edges', conditions: [{ field: 'session_count', op: '>=', value: 6 }, { field: 'session_count', op: '<=', value: 20 }], logic: 'and' } },
    { dot: false, fill: '#d29922', label: '21–100 sessions',
      filter: { target: 'edges', conditions: [{ field: 'session_count', op: '>=', value: 21 }, { field: 'session_count', op: '<=', value: 100 }], logic: 'and' } },
    { dot: false, fill: '#f85149', label: '100+ sessions',
      filter: { target: 'edges', conditions: [{ field: 'session_count', op: '>', value: 100 }] } },
  ],
};
