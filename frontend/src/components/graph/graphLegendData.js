// Shared legend data used by GraphOptionsPanel (sidebar) and GraphLegend (canvas overlay).

export const NODE_LEGENDS = {
  address: [
    { dot: true,  fill: 'var(--node-private)',  stroke: 'var(--node-private-s)',  label: 'Private (RFC1918)' },
    { dot: true,  fill: 'var(--node-external)', stroke: 'var(--node-external-s)', label: 'External' },
    { dot: true,  fill: 'var(--node-gateway)',  stroke: 'var(--node-gateway-s)',  label: 'Gateway' },
    { dot: true,  fill: 'var(--node-subnet)',   stroke: 'var(--node-subnet-s)',   label: 'Subnet node' },
  ],
  os: [
    { dot: true, fill: '#0d2137', stroke: '#388bfd', label: 'Windows' },
    { dot: true, fill: '#0d2a1a', stroke: '#3fb950', label: 'Linux / Unix' },
    { dot: true, fill: '#1c1c1c', stroke: '#8b949e', label: 'macOS' },
    { dot: true, fill: '#2a1a10', stroke: '#d29922', label: 'Network device' },
    { dot: true, fill: '#1c1122', stroke: '#bc8cff', label: 'Unknown' },
  ],
  protocol: [
    { dot: true, fill: '#0d1f3a', stroke: '#1f6feb', label: 'TCP dominant' },
    { dot: true, fill: '#061520', stroke: '#388bfd', label: 'TLS dominant' },
    { dot: true, fill: '#0d2a1a', stroke: '#3fb950', label: 'DNS dominant' },
    { dot: true, fill: '#2a1e0d', stroke: '#d29922', label: 'HTTP dominant' },
  ],
  volume: [
    { dot: true, fill: '#0d2a1a', stroke: '#3fb950', label: 'Low  (< 100 KB)' },
    { dot: true, fill: '#2a2010', stroke: '#d29922', label: 'Medium  (< 1 MB)' },
    { dot: true, fill: '#2a1a10', stroke: '#f0883e', label: 'High  (< 10 MB)' },
    { dot: true, fill: '#2a1010', stroke: '#f85149', label: 'Very high  (≥ 10 MB)' },
  ],
};

export const EDGE_LEGENDS = {
  protocol: [
    { dot: false, fill: '#1f6feb', label: 'TCP' },
    { dot: false, fill: '#388bfd', label: 'TLS' },
    { dot: false, fill: '#3fb950', label: 'DNS' },
    { dot: false, fill: '#d29922', label: 'HTTP' },
  ],
  volume: [
    { dot: false, fill: '#3fb950', label: 'Low  (< 100 KB)' },
    { dot: false, fill: '#d29922', label: 'Medium  (< 1 MB)' },
    { dot: false, fill: '#f0883e', label: 'High  (< 10 MB)' },
    { dot: false, fill: '#f85149', label: 'Very high  (≥ 10 MB)' },
  ],
  sessions: [
    { dot: false, fill: '#388bfd', label: '1–5 sessions' },
    { dot: false, fill: '#3fb950', label: '6–20 sessions' },
    { dot: false, fill: '#d29922', label: '21–100 sessions' },
    { dot: false, fill: '#f85149', label: '100+ sessions' },
  ],
};
