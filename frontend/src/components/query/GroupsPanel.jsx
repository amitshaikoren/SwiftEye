/**
 * GroupsPanel — browse recorded tag/color/cluster/set snapshots.
 *
 * Fetches GET /api/query/groups. Refetches whenever the parent bumps
 * `refreshKey` (tied to pipeline runs) or the user hits the refresh button.
 * Entries are expandable: collapsed shows name + count + delete; expanded
 * shows the recipe slice that produced it and the clickable member list.
 */
import React, { useEffect, useState } from 'react';
import { fetchQueryGroups, deleteQueryGroup } from '../../api';

const KIND_META = {
  tag:     { label: 'Tags',     chipBg: 'rgba(126,231,135,.12)', chipFg: '#7ee787' },
  color:   { label: 'Colors',   chipBg: 'rgba(126,231,135,.12)', chipFg: '#7ee787' },
  cluster: { label: 'Clusters', chipBg: 'rgba(126,231,135,.12)', chipFg: '#7ee787' },
  set:     { label: 'Sets',     chipBg: 'rgba(210,168,255,.12)', chipFg: '#d2a8ff' },
};

const VERB_META = {
  highlight:   { fg: '#79c0ff', label: 'highlight' },
  show_only:   { fg: '#79c0ff', label: 'show only' },
  hide:        { fg: '#79c0ff', label: 'hide' },
  tag:         { fg: '#7ee787', label: 'tag' },
  color:       { fg: '#7ee787', label: 'color' },
  cluster:     { fg: '#7ee787', label: 'cluster' },
  save_as_set: { fg: '#d2a8ff', label: 'save as set' },
};

const DIALECT_COLOR = { cypher: '#7ee787', sql: '#79c0ff', pyspark: '#f5a623' };

function StepSummary({ step }) {
  const vm = VERB_META[step.verb] || VERB_META.highlight;
  const target = step.target || 'nodes';
  const isFreehand = (step.kind === 'freehand') || !!step.text;

  let body;
  if (isFreehand) {
    const t = (step.text || '').replace(/\s+/g, ' ').trim();
    const truncated = t.length > 72 ? t.slice(0, 70) + '…' : t;
    const dc = DIALECT_COLOR[step.dialect] || 'var(--txD)';
    body = (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
        {step.dialect && (
          <span style={{
            fontSize: 9, padding: '1px 5px', borderRadius: 3, fontFamily: 'var(--fn)',
            color: dc, border: `1px solid ${dc}40`,
          }}>{step.dialect}</span>
        )}
        <span style={{
          fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--tx)',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>{truncated || <em style={{ color: 'var(--txD)' }}>empty</em>}</span>
      </span>
    );
  } else {
    const conds = (step.conditions || []).filter(c => c.field && c.op);
    const parts = conds.map(c => {
      const v = c.value !== undefined && c.value !== '' ? ` ${c.value}` : '';
      return `${c.field} ${c.op}${v}`;
    });
    body = (
      <span style={{ fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--tx)' }}>
        {parts.length ? parts.join(` ${step.logic || 'AND'} `) : <em style={{ color: 'var(--txD)' }}>no conditions</em>}
      </span>
    );
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '3px 0', minWidth: 0 }}>
      <span style={{
        fontSize: 9, fontFamily: 'var(--fn)', fontWeight: 600,
        padding: '1px 6px', borderRadius: 3, background: 'rgba(88,166,255,.08)', color: vm.fg,
      }}>{vm.label}</span>
      <span style={{
        fontSize: 9, padding: '1px 5px', border: '1px solid var(--bd)', borderRadius: 10,
        color: 'var(--txD)',
      }}>{target}</span>
      {body}
      {step.group_name && (
        <span style={{ fontSize: 9, fontFamily: 'var(--fn)', color: '#d2a8ff', marginLeft: 'auto' }}>
          @{step.group_name}
        </span>
      )}
    </div>
  );
}

function GroupEntry({ kind, name, entry, onDelete, onSelectNode, onSelectEdge }) {
  const [open, setOpen] = useState(false);
  const meta = KIND_META[kind];
  const members = entry.members || [];
  const isEdges = entry.target === 'edges';
  const colorSwatch = kind === 'color' && entry.group_args?.color;

  function selectMember(id) {
    if (isEdges) onSelectEdge?.(id); else onSelectNode?.(id);
  }

  return (
    <div style={{
      border: '1px solid var(--bd)', borderRadius: 5, padding: '6px 10px',
      marginBottom: 4, background: 'var(--bg)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
        <button onClick={() => setOpen(o => !o)}
          style={{
            background: 'transparent', border: 0, cursor: 'pointer',
            color: 'var(--txD)', padding: 0, fontSize: 10, width: 14,
          }} title={open ? 'collapse' : 'expand'}>{open ? '▼' : '▶'}</button>
        {colorSwatch && (
          <span style={{
            width: 10, height: 10, background: colorSwatch, borderRadius: 2,
            border: '1px solid var(--bd)', display: 'inline-block', flexShrink: 0,
          }} />
        )}
        <span style={{ fontFamily: 'var(--fn)', fontSize: 11, color: '#d2a8ff',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          @{name}
        </span>
        <span style={{
          fontSize: 9, padding: '1px 5px', border: '1px solid var(--bd)', borderRadius: 10,
          color: 'var(--txD)', flexShrink: 0,
        }}>{entry.target}</span>
        <span style={{ flex: 1 }} />
        <span style={{ fontSize: 10, fontFamily: 'var(--fn)', color: '#7ee787', flexShrink: 0 }}>
          {members.length}
        </span>
        <button onClick={() => onDelete(kind, name)} title="delete group"
          style={{
            background: 'transparent', border: 0, cursor: 'pointer',
            color: '#f85149', padding: '0 4px', fontSize: 12,
          }}>✕</button>
      </div>

      {open && (
        <div style={{ marginTop: 6, paddingTop: 6, borderTop: '1px solid var(--bd)' }}>
          <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase',
            letterSpacing: '.06em', marginBottom: 4 }}>Recipe</div>
          <div style={{ marginBottom: 8 }}>
            {(entry.recipe || []).map((step, i) => (
              <StepSummary key={i} step={step} />
            ))}
          </div>
          <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase',
            letterSpacing: '.06em', marginBottom: 4 }}>Members ({members.length})</div>
          <div style={{ maxHeight: 140, overflowY: 'auto',
            border: '1px solid var(--bd)', borderRadius: 4, padding: 4 }}>
            {members.length === 0 ? (
              <div style={{ fontSize: 10, color: 'var(--txD)', padding: '4px 2px' }}>
                No members.
              </div>
            ) : members.map(id => (
              <div key={id}
                onClick={() => selectMember(id)}
                title="select in graph"
                style={{
                  fontFamily: 'var(--fn)', fontSize: 10, padding: '2px 6px',
                  cursor: 'pointer', color: 'var(--tx)', borderRadius: 3,
                }}
                onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,.08)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              >
                {id}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function GroupsPanel({ loaded, refreshKey, onSelectNode, onSelectEdge }) {
  const [data, setData] = useState({ tag: {}, color: {}, cluster: {}, set: {} });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function reload() {
    if (!loaded) { setData({ tag: {}, color: {}, cluster: {}, set: {} }); return; }
    setLoading(true); setError('');
    try {
      const d = await fetchQueryGroups();
      setData(d || { tag: {}, color: {}, cluster: {}, set: {} });
    } catch (e) {
      setError(e.message || 'Failed to load groups');
    }
    setLoading(false);
  }

  useEffect(() => { reload(); /* eslint-disable-next-line */ }, [loaded, refreshKey]);

  async function handleDelete(kind, name) {
    try { await deleteQueryGroup(kind, name); await reload(); }
    catch (e) { setError(e.message || 'Delete failed'); }
  }

  const totalCount = Object.values(data).reduce((n, bucket) => n + Object.keys(bucket || {}).length, 0);

  return (
    <div style={{ padding: '14px 18px' }}>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between',
        marginBottom: 8 }}>
        <h2 style={sectionLabel}>Groups</h2>
        <button onClick={reload} disabled={loading}
          style={{
            fontSize: 10, padding: '3px 10px', cursor: 'pointer',
            background: 'transparent', color: 'var(--txD)',
            border: '1px solid var(--bd)', borderRadius: 'var(--rs)',
            opacity: loading ? 0.5 : 1,
          }}>{loading ? '…' : 'Refresh'}</button>
      </div>

      {error && (
        <div style={{
          marginBottom: 8, fontSize: 10, color: '#f85149', padding: '5px 9px',
          background: 'rgba(248,81,73,.06)', border: '1px solid rgba(248,81,73,.15)',
          borderRadius: 5,
        }}>{error}</div>
      )}

      {!loaded ? (
        <div style={{ fontSize: 10, color: 'var(--txD)', padding: '6px 2px' }}>
          Load a capture to use groups.
        </div>
      ) : totalCount === 0 ? (
        <div style={{ fontSize: 10, color: 'var(--txD)', padding: '10px 2px' }}>
          No groups yet. Add a <code>tag</code>, <code>color</code>, <code>cluster</code>, or <code>save_as_set</code> step
          to your recipe to populate this.
        </div>
      ) : (
        Object.entries(KIND_META).map(([kind, meta]) => {
          const bucket = data[kind] || {};
          const names = Object.keys(bucket);
          if (names.length === 0) return null;
          return (
            <div key={kind} style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <span style={{
                  fontFamily: 'var(--fn)', fontWeight: 600, fontSize: 10,
                  padding: '2px 7px', borderRadius: 3,
                  background: meta.chipBg, color: meta.chipFg,
                }}>{meta.label}</span>
                <span style={{ fontSize: 10, color: 'var(--txD)' }}>{names.length}</span>
              </div>
              {names.map(name => (
                <GroupEntry key={name} kind={kind} name={name}
                  entry={bucket[name]} onDelete={handleDelete}
                  onSelectNode={onSelectNode} onSelectEdge={onSelectEdge} />
              ))}
            </div>
          );
        })
      )}
    </div>
  );
}

const sectionLabel = {
  fontSize: 11, margin: 0, color: 'var(--txD)',
  textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600,
};
