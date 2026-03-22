/**
 * Auto-discovery registry for protocol session sections.
 *
 * Drop a .jsx file in this directory exporting:
 *   hasData(s)    — boolean guard
 *   title(s)      — string section title
 *   defaultOpen   — boolean (default false)
 *   order         — number for display ordering
 *   prefix        — string or string[] of field prefixes this section claims
 *   default       — React component receiving { s }
 *
 * The section appears automatically in SessionDetail under Application (L5+).
 */
import React from 'react';
import Collapse from '../Collapse';
import Row from '../Row';

// ── Auto-discover all .jsx siblings ────────────────────────────────
const modules = import.meta.glob('./*.jsx', { eager: true });

const _sections = [];
for (const [path, mod] of Object.entries(modules)) {
  const id = path.replace('./', '').replace('.jsx', '');
  _sections.push({
    id,
    hasData:     mod.hasData     || (() => false),
    title:       mod.title       || (() => id),
    defaultOpen: mod.defaultOpen || false,
    order:       mod.order       ?? 999,
    prefix:      Array.isArray(mod.prefix) ? mod.prefix : (mod.prefix ? [mod.prefix] : [`${id}_`]),
    Component:   mod.default,
  });
}
_sections.sort((a, b) => a.order - b.order);

export const sections = _sections;

// ── Core session key prefixes (NOT protocol data) ──────────────────
const CORE_PREFIXES = new Set([
  'fwd_', 'rev_', 'src_', 'dst_', 'initiator_', 'responder_',
  'packet_', 'total_', 'payload_', 'start_', 'end_', 'has_', 'flag_',
  'window_', 'seq_', 'ack_', 'tcp_', 'ip_', 'ip6_',
  'ttl', 'source_', 'init_window', 'zeek_',
]);

function isCoreKey(key) {
  for (const cp of CORE_PREFIXES) {
    if (key.startsWith(cp)) return true;
  }
  // Non-prefixed keys (id, protocol, transport, duration, etc.)
  return !key.includes('_');
}

// ── Unclaimed prefix detection ─────────────────────────────────────
export function getUnclaimedPrefixes(s, secs) {
  const claimed = new Set();
  for (const sec of secs) {
    for (const p of sec.prefix) claimed.add(p);
  }

  const groups = new Map(); // prefix -> [key, ...]
  for (const key of Object.keys(s)) {
    if (isCoreKey(key)) continue;
    const idx = key.indexOf('_');
    if (idx < 1) continue;
    const prefix = key.slice(0, idx + 1);
    if (claimed.has(prefix)) continue;
    // Only include keys that have actual data (skip defaults/empties)
    const v = s[key];
    if (v == null || v === false || v === 0 || v === '') continue;
    if (Array.isArray(v) && v.length === 0) continue;
    if (typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === 0) continue;
    if (!groups.has(prefix)) groups.set(prefix, []);
    groups.get(prefix).push(key);
  }
  return groups;
}

// ── Helpers ─────────────────────────────────────────────────────────
function humanize(key, prefix) {
  const rest = key.slice(prefix.length);
  return rest.replace(/_/g, ' ').replace(/^\w/, c => c.toUpperCase());
}

function formatValue(v) {
  if (Array.isArray(v)) return v.join(', ');
  if (typeof v === 'boolean') return v ? 'yes' : 'no';
  if (typeof v === 'object' && v !== null) return JSON.stringify(v);
  return String(v);
}

// ── Fallback renderer for unclaimed protocol prefixes ──────────────
export function FallbackSection({ s, prefix, keys }) {
  const label = prefix.replace(/_$/, '').replace(/_/g, ' ').replace(/^\w/, c => c.toUpperCase());
  return (
    <Collapse title={label}>
      {keys.map(k => (
        <Row key={k} l={humanize(k, prefix)} v={formatValue(s[k])} />
      ))}
    </Collapse>
  );
}
