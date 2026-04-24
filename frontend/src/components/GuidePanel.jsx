/**
 * GuidePanel — field reference for the three query primitives.
 *
 * Three sections: Nodes / Edges / Sessions.
 * Each section shows collapsible cards per field group with name, type badge, and description.
 * Fetches /api/query/schema on mount — no capture required for the declarative catalog.
 */
import React, { useEffect, useState } from 'react';
import { fetchQuerySchema } from '../api';

const TYPE_META = {
  numeric: { label: 'Num',  color: '#79c0ff', bg: 'rgba(88,166,255,.12)',  border: 'rgba(88,166,255,.35)' },
  number:  { label: 'Num',  color: '#79c0ff', bg: 'rgba(88,166,255,.12)',  border: 'rgba(88,166,255,.35)' },
  set:     { label: 'Set',  color: '#d2a8ff', bg: 'rgba(210,168,255,.12)', border: 'rgba(210,168,255,.35)' },
  list:    { label: 'List', color: '#d2a8ff', bg: 'rgba(210,168,255,.12)', border: 'rgba(210,168,255,.35)' },
  boolean: { label: 'Bool', color: '#7ee787', bg: 'rgba(63,185,80,.12)',   border: 'rgba(63,185,80,.35)' },
  string:  { label: 'Text', color: '#ffa657', bg: 'rgba(255,166,87,.12)',  border: 'rgba(255,166,87,.35)' },
};

function TypeBadge({ type }) {
  const m = TYPE_META[type] || { label: type, color: 'var(--txD)', bg: 'var(--bgC)', border: 'var(--bd)' };
  return (
    <span style={{
      fontSize: 9, fontFamily: 'var(--fn)', padding: '2px 5px', borderRadius: 3,
      background: m.bg, color: m.color, border: `1px solid ${m.border}`,
      whiteSpace: 'nowrap', flexShrink: 0, fontWeight: 600, letterSpacing: '.04em',
    }}>
      {m.label}
    </span>
  );
}

function FieldRow({ field }) {
  return (
    <div style={{ display: 'flex', alignItems: 'baseline', gap: 7, padding: '4px 0', borderBottom: '1px solid var(--bd)' }}>
      <TypeBadge type={field.type} />
      <span style={{ fontSize: 11, fontFamily: 'var(--fn)', color: 'var(--tx)', flexShrink: 0 }}>
        {field.name}
      </span>
      {field.description && (
        <span style={{ fontSize: 10, color: 'var(--txD)', fontFamily: 'var(--fn)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {field.description}
        </span>
      )}
    </div>
  );
}

function GroupCard({ group, fields }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ marginBottom: 8, border: '1px solid var(--bd)', borderRadius: 6, overflow: 'hidden' }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          width: '100%', padding: '6px 10px', background: 'var(--bgC)', border: 'none',
          cursor: 'pointer', textAlign: 'left',
        }}
      >
        <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--tx)', fontFamily: 'var(--fd)', textTransform: 'capitalize' }}>
          {group}
        </span>
        <span style={{ fontSize: 10, color: 'var(--txD)' }}>
          {open ? '▾' : '▸'} {fields.length}
        </span>
      </button>
      {open && (
        <div style={{ padding: '4px 10px 6px', background: 'var(--bg)' }}>
          {fields.map(f => <FieldRow key={f.name} field={f} />)}
        </div>
      )}
    </div>
  );
}

function PluginCard({ title, fields }) {
  const [open, setOpen] = useState(false);
  if (!fields || Object.keys(fields).length === 0) return null;
  const fieldList = Object.entries(fields).map(([name, type]) => ({ name, type, description: '' }));
  return <GroupCard group={title} fields={fieldList} />;
}

function NodesSection({ schema }) {
  const { node_groups = [], plugin_node_fields = {} } = schema;
  const hasPlugin = Object.keys(plugin_node_fields).length > 0;
  return (
    <div>
      <SectionHint text="Per-IP aggregates in the analysis graph." />
      {node_groups.map(g => <GroupCard key={g.group} group={g.group} fields={g.fields} />)}
      {hasPlugin && <PluginCard title="Plugin fields" fields={plugin_node_fields} />}
      {node_groups.length === 0 && !hasPlugin && <EmptyNote text="No node fields declared." />}
    </div>
  );
}

function EdgesSection({ schema }) {
  const { edge_groups = [], plugin_edge_fields = {} } = schema;
  const hasPlugin = Object.keys(plugin_edge_fields).length > 0;
  return (
    <div>
      <SectionHint text="Per-IP-pair aggregates. All protocols merged across sessions." />
      {edge_groups.map(g => <GroupCard key={g.group} group={g.group} fields={g.fields} />)}
      {hasPlugin && <PluginCard title="Plugin fields" fields={plugin_edge_fields} />}
      {edge_groups.length === 0 && !hasPlugin && <EmptyNote text="No edge fields declared." />}
    </div>
  );
}

function SessionsSection({ schema }) {
  const { session_groups = [] } = schema;
  return (
    <div>
      <SectionHint text="Per-flow (5-tuple) session fields. Richest protocol detail." />
      <div style={{
        fontSize: 10, color: '#ffa657', background: 'rgba(255,166,87,.08)',
        border: '1px solid rgba(255,166,87,.25)', borderRadius: 5,
        padding: '7px 10px', marginBottom: 10,
      }}>
        Session querying is informational in this release — coming in Plan 2.
      </div>
      {session_groups.map(g => <GroupCard key={g.group} group={g.group} fields={g.fields} />)}
      {session_groups.length === 0 && <EmptyNote text="No session fields declared." />}
    </div>
  );
}

function SectionHint({ text }) {
  return (
    <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 10, fontFamily: 'var(--fn)' }}>
      {text}
    </div>
  );
}

function EmptyNote({ text }) {
  return (
    <div style={{ fontSize: 11, color: 'var(--txD)', padding: '8px 0' }}>{text}</div>
  );
}

const SECTIONS = ['nodes', 'edges', 'sessions'];

export default function GuidePanel({ loaded }) {
  const [schema, setSchema] = useState({});
  const [loading, setLoading] = useState(true);
  const [section, setSection] = useState('nodes');

  useEffect(() => {
    setLoading(true);
    fetchQuerySchema().then(s => { setSchema(s); setLoading(false); });
  }, [loaded]);

  const segStyle = (active) => ({
    fontSize: 11, padding: '4px 12px', cursor: 'pointer', border: 'none',
    background: active ? 'var(--ac)' : 'var(--bgC)',
    color: active ? '#fff' : 'var(--txD)',
    fontFamily: 'var(--fd)', fontWeight: active ? 600 : 400,
    borderRadius: 4,
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0, background: 'var(--bg)' }}>
      <div style={{ padding: '12px 14px 0', flexShrink: 0 }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--tx)', fontFamily: 'var(--fd)', marginBottom: 4 }}>
          Field Guide
        </div>
        <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 10 }}>
          All queryable fields by primitive. Use these names in queries.
        </div>
        <div style={{ display: 'flex', gap: 4, marginBottom: 12 }}>
          {SECTIONS.map(s => (
            <button key={s} onClick={() => setSection(s)} style={segStyle(section === s)}>
              {s.charAt(0).toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', padding: '0 14px 16px' }}>
        {loading ? (
          <div style={{ color: 'var(--txD)', fontSize: 11, marginTop: 20, textAlign: 'center' }}>
            Loading…
          </div>
        ) : (
          <>
            {section === 'nodes'    && <NodesSection    schema={schema} />}
            {section === 'edges'    && <EdgesSection    schema={schema} />}
            {section === 'sessions' && <SessionsSection schema={schema} />}
          </>
        )}
      </div>

      {!loaded && (
        <div style={{
          flexShrink: 0, fontSize: 10, color: 'var(--txD)', textAlign: 'center',
          padding: '6px 0', borderTop: '1px solid var(--bd)',
        }}>
          No capture loaded — showing declarative catalog only
        </div>
      )}
    </div>
  );
}
