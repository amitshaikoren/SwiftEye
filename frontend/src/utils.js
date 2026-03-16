/**
 * Shared utility / formatting functions for SwiftEye.
 */

export function fB(b) {
  if (b == null) return '0 B';
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(2) + ' GB';
}

export function fD(s) {
  if (!s || s < 0.001) return '0ms';
  if (s < 1) return (s * 1000).toFixed(0) + 'ms';
  if (s < 60) return s.toFixed(1) + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm ' + Math.floor(s % 60) + 's';
  return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
}

export function fN(n) {
  return typeof n === 'number' ? n.toLocaleString() : String(n || '');
}

/**
 * Format a Unix timestamp for display.
 * Always includes date + time so captures spanning midnight or spanning days
 * are not ambiguous.  Uses the locale's short date + time format.
 */
export function fT(ts) {
  if (!ts) return '';
  const d = new Date(ts * 1000);
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
    + ' ' + d.toLocaleTimeString();
}

/**
 * Format a Unix timestamp showing time only (for dense sparkline labels where
 * the date is already established by context).
 */
export function fTtime(ts) {
  return ts ? new Date(ts * 1000).toLocaleTimeString() : '';
}

/** TCP flag display colors */
export const FLAG_COLORS = {
  SYN: '#3fb950', ACK: '#58a6ff', FIN: '#d29922', RST: '#f85149',
  PSH: '#bc8cff', URG: '#f97316', ECE: '#22d3ee', CWR: '#94a3b8',
};

/** TCP flag tooltip descriptions */
export const FLAG_TIPS = {
  SYN: 'Connection initiation request',
  ACK: 'Acknowledgment',
  FIN: 'Connection termination (graceful close)',
  RST: 'Connection reset (abrupt termination)',
  PSH: 'Push - deliver data immediately',
  URG: 'Urgent data pointer active',
  ECE: 'ECN-Echo congestion notification',
  CWR: 'Congestion Window Reduced',
  HS: 'TCP Handshake completed (SYN→SYN+ACK→ACK)',
};

/** Build protocol hierarchy tree from stats.
 *  Uses the transport field provided by the backend on each protocol entry,
 *  so the frontend doesn't need to know which protocols run over TCP vs UDP.
 */
export function buildProtoTree(stats) {
  if (!stats?.protocols) return [];
  const byTransport = {};

  for (const [proto, d] of Object.entries(stats.protocols)) {
    // Backend provides d.transport ("TCP", "UDP", "ICMP", "ARP", "OTHER", "")
    // Fall back to the protocol name itself for transport-level entries (e.g. "TCP" protocol on "TCP" transport)
    let parent = d.transport || 'OTHER';
    // If the protocol IS a transport name, it's a top-level entry
    if (['TCP', 'UDP', 'ICMP', 'ARP', 'OTHER'].includes(proto)) {
      parent = proto;
    }

    if (!byTransport[parent]) byTransport[parent] = { children: {}, pkts: 0, bytes: 0 };
    byTransport[parent].pkts += d.packets;
    byTransport[parent].bytes += d.bytes;
    if (proto !== parent) byTransport[parent].children[proto] = d;
  }

  return Object.entries(byTransport)
    .filter(([, v]) => v.pkts > 0)
    .sort((a, b) => b[1].bytes - a[1].bytes)
    .map(([name, v]) => ({
      name,
      pkts: v.pkts,
      bytes: v.bytes,
      children: Object.entries(v.children)
        .sort((a, b) => b[1].bytes - a[1].bytes)
        .map(([n, d]) => ({ name: n, pkts: d.packets, bytes: d.bytes })),
    }));
}
