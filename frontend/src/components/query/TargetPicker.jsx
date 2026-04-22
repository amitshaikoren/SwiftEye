/**
 * TargetPicker — unified target dropdown for Visual editors.
 *
 * Lists "All nodes", "All edges", then one entry per recorded group
 * (@name across tag/color/cluster/set). Emits `{target, fromGroup}` on
 * change: picking a @group resolves `target` to the group's own target
 * and sets `fromGroup = {kind, name}`; picking All-nodes/All-edges
 * clears `fromGroup`.
 *
 * Fetches the groups list once per `refreshKey` bump (parent should
 * increment after pipeline runs so newly-created groups appear).
 */
import React, { useEffect, useState } from 'react';
import { fetchQueryGroups } from '../../api';

const KIND_ORDER = ['tag', 'color', 'cluster', 'set'];
const KIND_LABEL = { tag: 'Tags', color: 'Colors', cluster: 'Clusters', set: 'Sets' };

function encodeGroup(kind, name) { return `g:${kind}:${encodeURIComponent(name)}`; }
function decodeGroup(v) {
  const rest = v.slice(2);
  const i = rest.indexOf(':');
  return { kind: rest.slice(0, i), name: decodeURIComponent(rest.slice(i + 1)) };
}

export default function TargetPicker({ target, fromGroup, onChange, refreshKey, style }) {
  const [groups, setGroups] = useState({ tag: {}, color: {}, cluster: {}, set: {} });

  useEffect(() => {
    let alive = true;
    fetchQueryGroups()
      .then(d => { if (alive) setGroups(d || { tag: {}, color: {}, cluster: {}, set: {} }); })
      .catch(() => {});
    return () => { alive = false; };
  }, [refreshKey]);

  const exists = fromGroup && (groups[fromGroup.kind] || {})[fromGroup.name];
  const value = fromGroup ? encodeGroup(fromGroup.kind, fromGroup.name) : target;

  function handleChange(e) {
    const v = e.target.value;
    if (v.startsWith('g:')) {
      const { kind, name } = decodeGroup(v);
      const entry = (groups[kind] || {})[name];
      onChange({ target: entry?.target || target, fromGroup: { kind, name } });
    } else {
      onChange({ target: v, fromGroup: null });
    }
  }

  const selectStyle = {
    fontSize: 11, fontFamily: 'var(--fn)', padding: '4px 8px',
    background: 'var(--bgC)', color: 'var(--tx)', border: '1px solid var(--bd)',
    borderRadius: 'var(--rs)', outline: 'none', cursor: 'pointer', minWidth: 160,
    ...(style || {}),
  };

  return (
    <select value={value} onChange={handleChange} style={selectStyle}>
      <optgroup label="All">
        <option value="nodes">All nodes</option>
        <option value="edges">All edges</option>
      </optgroup>
      {KIND_ORDER.map(kind => {
        const entries = Object.entries(groups[kind] || {});
        const showMissing = fromGroup && fromGroup.kind === kind && !exists;
        if (!entries.length && !showMissing) return null;
        return (
          <optgroup key={kind} label={KIND_LABEL[kind]}>
            {entries.map(([name, info]) => (
              <option key={name} value={encodeGroup(kind, name)}>
                @{name} ({info.target || 'nodes'}, {(info.members || []).length})
              </option>
            ))}
            {showMissing && (
              <option value={encodeGroup(kind, fromGroup.name)}>@{fromGroup.name} (missing)</option>
            )}
          </optgroup>
        );
      })}
    </select>
  );
}
