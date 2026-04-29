/**
 * Source capability registry.
 *
 * Each data source (pcap, zeek, …) declares the UI capabilities it provides.
 * Tabs and sections in SessionDetail check capabilities — not source_type
 * strings — so adding a new source is one registry entry, not a hunt through JSX.
 *
 * Shared features (TCP flags, byte counts, protocol sections like DNS/HTTP/TLS)
 * don't need a capability — they use per-field data checks because multiple
 * sources can provide them.
 */

const SOURCE_CAPS = {
  // Raw packet capture — full packet-level resolution
  pcap: [
    'raw_packets',     // per-packet list (Packets tab)
    'payload',         // payload hex dump + entropy (Payload tab)
    'charts',          // seq/ack timeline, bytes/time (Charts tab)
    'l3_headers',      // IP header details: DSCP, ECN, DF/MF, fragmentation, IP ID
    'tcp_options',     // TCP options (MSS, Window Scale, SACK, etc.)
    'window_size',     // TCP window size tracking (init, min, max)
    'seq_ack',         // sequence/ack number tracking (ISN, first/last)
    'tcp_reliability', // retransmits, out-of-order, dup-ACKs
  ],

  // Zeek log aggregation — connection-level metadata
  zeek: [
    'zeek_conn',       // connection state, history string, service, UID
  ],
};

// ── Helpers ─────────────────────────────────────────────────────────

/** Get the capability set for a session. Defaults to pcap if no source_type. */
export function getCaps(session) {
  const source = session?.source_type || 'pcap';
  return new Set(SOURCE_CAPS[source] || SOURCE_CAPS.pcap);
}

/** Check whether a session has a specific capability. */
export function hasCap(session, cap) {
  return getCaps(session).has(cap);
}

/** The registry itself, exported for introspection / debugging. */
export { SOURCE_CAPS };
