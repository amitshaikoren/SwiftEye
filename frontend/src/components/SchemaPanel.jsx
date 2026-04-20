/**
 * SchemaPanel — reference view of node/edge fields exposed by the current capture.
 *
 * Data from `/api/query/schema` (flat `{ node_fields, edge_fields }` — name→type).
 * Fields are grouped by type (Numeric / Sets / Flags / Text) for quick scanning.
 */
import React, { useEffect, useState } from 'react';
import { fetchQuerySchema } from '../api';

const TYPE_META = {
  numeric: { label: 'Numeric', color: '#79c0ff', bg: 'rgba(88,166,255,.1)', border: 'rgba(88,166,255,.3)' },
  set:     { label: 'Set',     color: '#d2a8ff', bg: 'rgba(210,168,255,.1)', border: 'rgba(210,168,255,.3)' },
  boolean: { label: 'Flag',    color: '#7ee787', bg: 'rgba(63,185,80,.1)',  border: 'rgba(63,185,80,.3)' },
  string:  { label: 'Text',    color: '#ffa657', bg: 'rgba(255,166,87,.1)', border: 'rgba(255,166,87,.3)' },
};

const GROUP_ORDER = [
  ['numeric', 'Numeric'],
  ['set',     'Sets'],
  ['boolean', 'Flags'],
  ['string',  'Text'],
];

function groupByType(fields) {
  const out = { numeric: [], set: [], boolean: [], string: [] };
  for (const [name, type] of Object.entries(fields || {})) {
    if (name === 'session_ids') continue;
    (out[type] ||= []).push(name);
  }
  for (const k of Object.keys(out)) out[k].sort();
  return out;
}

function FieldChip({ name, type }) {
  const meta = TYPE_META[type] || { color: 'var(--txD)', bg: 'var(--bgC)', border: 'var(--bd)' };
  return (
    <span
      title={`${name} — ${type}`}
      style={{
        fontSize: 11, fontFamily: 'var(--fn)', padding: '3px 8px', borderRadius: 4,
        background: meta.bg, color: meta.color, border: `1px solid ${meta.border}`,
        whiteSpace: 'nowrap',
      }}
    >
      {name}
    </span>
  );
}

function EntitySection({ title, fields, total }) {
  const grouped = groupByType(fields);
  const hasAny = Object.values(grouped).some(arr => arr.length > 0);

  return (
    <div style={{ marginBottom: 18 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 8 }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--tx)', fontFamily: 'var(--fd)' }}>
          {title}
        </div>
        <div style={{ fontSize: 10, color: 'var(--txD)', fontFamily: 'var(--fn)' }}>
          {total} field{total === 1 ? '' : 's'}
        </div>
      </div>
      {!hasAny && (
        <div style={{ fontSize: 11, color: 'var(--txD)', padding: '6px 0' }}>
          No fields declared.
        </div>
      )}
      {GROUP_ORDER.map(([typeKey, label]) => {
        const entries = grouped[typeKey];
        if (!entries || entries.length === 0) return null;
        const meta = TYPE_META[typeKey];
        return (
          <div key={typeKey} style={{ marginBottom: 10 }}>
            <div style={{
              fontSize: 9, color: meta.color, fontWeight: 600, marginBottom: 5,
              textTransform: 'uppercase', letterSpacing: '.06em',
            }}>
              {label} · {entries.length}
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {entries.map(n => <FieldChip key={n} name={n} type={typeKey} />)}
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default function SchemaPanel({ loaded }) {
  const [schema, setSchema] = useState({ node_fields: {}, edge_fields: {} });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!loaded) { setSchema({ node_fields: {}, edge_fields: {} }); return; }
    setLoading(true);
    fetchQuerySchema().then(s => { setSchema(s); setLoading(false); });
  }, [loaded]);

  const nodeCount = Object.keys(schema.node_fields || {}).filter(k => k !== 'session_ids').length;
  const edgeCount = Object.keys(schema.edge_fields || {}).filter(k => k !== 'session_ids').length;

  return (
    <div style={{ overflowY: 'auto', padding: '16px 18px', background: 'var(--bg)', height: '100%' }}>
      <div style={{ marginBottom: 14 }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--tx)', fontFamily: 'var(--fd)', marginBottom: 4 }}>
          Schema
        </div>
        <div style={{ fontSize: 10, color: 'var(--txD)' }}>
          Fields available on nodes and edges. Use these names in queries.
        </div>
      </div>

      {!loaded && (
        <div style={{ color: 'var(--txD)', fontSize: 11, marginTop: 30, textAlign: 'center' }}>
          No capture loaded.
        </div>
      )}

      {loaded && loading && (
        <div style={{ color: 'var(--txD)', fontSize: 11, marginTop: 30, textAlign: 'center' }}>
          Loading schema…
        </div>
      )}

      {loaded && !loading && (
        <>
          <EntitySection title="Nodes" fields={schema.node_fields} total={nodeCount} />
          <EntitySection title="Edges" fields={schema.edge_fields} total={edgeCount} />
        </>
      )}
    </div>
  );
}
