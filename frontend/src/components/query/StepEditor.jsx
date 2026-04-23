/**
 * StepEditor — inline editor for one recipe step.
 *
 * Visual kind: target + conditions list (reuses OPS_BY_TYPE/NO_VALUE_OPS
 * from QueryBuilder). Freehand kind: dialect tabs + textarea, re-parsed on
 * change (debounced) so the structured fields stay in sync for the pipeline.
 */
import React, { useEffect, useMemo, useRef, useState } from 'react';
import { OPS_BY_TYPE, NO_VALUE_OPS, ACTIONS_REQUIRE_GROUP } from '../QueryBuilder';
import { parseQueryText } from '../../api';
import TargetPicker from './TargetPicker';

const SELECT = {
  fontSize: 11, fontFamily: 'var(--fn)', padding: '4px 8px',
  background: 'var(--bgC)', color: 'var(--tx)', border: '1px solid var(--bd)',
  borderRadius: 'var(--rs)', outline: 'none', cursor: 'pointer',
};
const INPUT = { ...SELECT, cursor: 'text', flex: 1, minWidth: 60 };

function groupFields(fields) {
  const g = { Numeric: [], Sets: [], Flags: [], Text: [] };
  for (const [name, type] of Object.entries(fields || {})) {
    if (name === 'session_ids') continue;
    const entry = { name, label: name.replace(/_/g, ' '), type };
    if (type === 'numeric') g.Numeric.push(entry);
    else if (type === 'set') g.Sets.push(entry);
    else if (type === 'boolean') g.Flags.push(entry);
    else g.Text.push(entry);
  }
  return g;
}

function VisualEditor({ step, schema, onChange, groupsRefreshKey }) {
  const fields = step.target === 'edges' ? schema.edge_fields : schema.node_fields;
  const fieldGroups = useMemo(() => groupFields(fields), [fields]);

  function getType(name) { return (fields || {})[name] || 'string'; }

  function updateCondition(idx, patch) {
    const next = (step.conditions || []).map((c, i) => {
      if (i !== idx) return c;
      const merged = { ...c, ...patch };
      if (patch.field !== undefined && patch.field !== c.field) {
        const ops = OPS_BY_TYPE[getType(patch.field)] || [];
        merged.op = ops[0]?.op || '';
        merged.value = '';
      }
      return merged;
    });
    onChange({ conditions: next });
  }

  function addCondition() {
    onChange({ conditions: [...(step.conditions || []), { field: '', op: '', value: '' }] });
  }
  function removeCondition(idx) {
    if ((step.conditions || []).length <= 1) return;
    onChange({ conditions: step.conditions.filter((_, i) => i !== idx) });
  }

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <span style={{ fontSize: 11, color: 'var(--txD)' }}>Find</span>
        <TargetPicker
          target={step.target || 'nodes'}
          fromGroup={step.from_group || null}
          refreshKey={groupsRefreshKey}
          onChange={({ target: t, fromGroup: fg }) => {
            // Reset conditions when switching between target types or in/out of a group,
            // since field options differ.
            onChange({
              target: t,
              from_group: fg || undefined,
              conditions: [{ field: '', op: '', value: '' }],
            });
          }}
        />
        {(step.conditions || []).length > 1 && (
          <div style={{ display: 'flex', gap: 4, marginLeft: 'auto' }}>
            {['AND', 'OR'].map(l => (
              <button key={l} onClick={() => onChange({ logic: l })}
                style={{
                  fontSize: 9, padding: '2px 7px', borderRadius: 'var(--rs)', cursor: 'pointer',
                  background: step.logic === l ? 'rgba(88,166,255,.12)' : 'transparent',
                  color: step.logic === l ? 'var(--ac)' : 'var(--txD)',
                  border: `1px solid ${step.logic === l ? 'var(--ac)' : 'var(--bd)'}`,
                }}>{l}</button>
            ))}
          </div>
        )}
      </div>

      {(step.conditions || []).map((cond, idx) => {
        const type = cond.field ? getType(cond.field) : null;
        const ops = type ? (OPS_BY_TYPE[type] || []) : [];
        const needsValue = cond.op && !NO_VALUE_OPS.has(cond.op);
        return (
          <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
            <select value={cond.field} onChange={e => updateCondition(idx, { field: e.target.value })}
              style={{ ...SELECT, minWidth: 100 }}>
              <option value="">field...</option>
              {Object.entries(fieldGroups).map(([group, items]) => (
                items.length > 0 && (
                  <optgroup key={group} label={group}>
                    {items.map(f => <option key={f.name} value={f.name}>{f.label}</option>)}
                  </optgroup>
                )
              ))}
            </select>
            {cond.field && (
              <select value={cond.op} onChange={e => updateCondition(idx, { op: e.target.value })}
                style={{ ...SELECT, minWidth: 80 }}>
                {ops.map(o => <option key={o.op} value={o.op}>{o.label}</option>)}
              </select>
            )}
            {needsValue && (
              <input value={cond.value} onChange={e => updateCondition(idx, { value: e.target.value })}
                placeholder="value" style={INPUT} />
            )}
            {(step.conditions || []).length > 1 && (
              <button onClick={() => removeCondition(idx)}
                style={{ fontSize: 11, padding: '2px 6px', background: 'transparent', color: 'var(--txD)',
                  border: '1px solid var(--bd)', borderRadius: 'var(--rs)', cursor: 'pointer' }}>×</button>
            )}
          </div>
        );
      })}

      <button onClick={addCondition}
        style={{ fontSize: 10, padding: '3px 10px', marginTop: 4, cursor: 'pointer',
          background: 'transparent', color: 'var(--txD)', border: '1px dashed var(--bd)',
          borderRadius: 'var(--rs)' }}>
        + condition
      </button>
    </div>
  );
}

const DIALECTS = [
  ['cypher', 'Cypher', '#7ee787', 'rgba(63,185,80,.12)'],
  ['sql', 'SQL', '#79c0ff', 'rgba(88,166,255,.12)'],
  ['pyspark', 'PySpark', '#f5a623', 'rgba(240,136,62,.12)'],
];

function FreehandEditor({ step, onChange }) {
  const [text, setText] = useState(step.text || '');
  const [dialect, setDialect] = useState(step.dialect || 'cypher');
  const [parseError, setParseError] = useState('');
  const [showError, setShowError] = useState(false);
  const parseTimer = useRef(null);
  const errorTimer = useRef(null);

  useEffect(() => {
    clearTimeout(parseTimer.current);
    clearTimeout(errorTimer.current);
    setShowError(false);
    if (!text.trim()) { setParseError(''); return; }
    parseTimer.current = setTimeout(async () => {
      try {
        const r = await parseQueryText(text, dialect);
        if (r?.error) {
          setParseError(r.error);
          errorTimer.current = setTimeout(() => setShowError(true), 600);
        } else if (r?.query) {
          setParseError('');
          onChange({
            text, dialect,
            target: r.query.target || 'nodes',
            conditions: r.query.conditions || [],
            logic: r.query.logic || 'AND',
          });
        }
      } catch (e) {
        setParseError('Parse request failed');
        errorTimer.current = setTimeout(() => setShowError(true), 600);
      }
    }, 400);
    return () => { clearTimeout(parseTimer.current); clearTimeout(errorTimer.current); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [text, dialect]);

  return (
    <div>
      <div style={{ display: 'flex', gap: 0, marginBottom: 6 }}>
        {DIALECTS.map(([d, label, color, bg], i) => (
          <button key={d} onClick={() => setDialect(d)}
            style={{
              fontSize: 10, padding: '3px 10px', cursor: 'pointer',
              background: dialect === d ? bg : 'transparent',
              color: dialect === d ? color : 'var(--txD)',
              border: `1px solid ${dialect === d ? color + '66' : 'var(--bd)'}`,
              borderLeft: i > 0 ? 'none' : undefined,
              borderRadius: i === 0 ? 'var(--rs) 0 0 var(--rs)' : i === DIALECTS.length - 1 ? '0 var(--rs) var(--rs) 0' : 0,
              fontWeight: dialect === d ? 600 : 400,
            }}>{label}</button>
        ))}
      </div>
      <textarea value={text} onChange={e => setText(e.target.value)} spellCheck={false}
        placeholder={dialect === 'cypher'
          ? 'MATCH (n) WHERE n.packets > 1000 RETURN n'
          : dialect === 'pyspark' ? 'nodes.filter(col("packets") > 1000)'
          : 'SELECT * FROM nodes WHERE packets > 1000'}
        style={{
          width: '100%', minHeight: 56, maxHeight: 140, resize: 'vertical',
          fontFamily: "'Cascadia Code', 'Fira Code', Consolas, monospace",
          fontSize: 11, lineHeight: 1.5, padding: '7px 9px',
          background: 'var(--bgC)', color: 'var(--tx)', border: '1px solid var(--bd)',
          borderRadius: 6, outline: 'none', boxSizing: 'border-box',
        }} />
      {showError && parseError && (
        <div style={{
          marginTop: 6, fontSize: 10, color: '#f85149', padding: '5px 9px',
          background: 'rgba(248,81,73,.06)', border: '1px solid rgba(248,81,73,.15)',
          borderRadius: 5, whiteSpace: 'pre-wrap',
        }}>{parseError}</div>
      )}
    </div>
  );
}

function VerbHeader({ step, onChange }) {
  const verb = step.verb || 'highlight';
  const needsGroup = ACTIONS_REQUIRE_GROUP.has(verb);

  function changeVerb(next) {
    const patch = { verb: next };
    if (ACTIONS_REQUIRE_GROUP.has(next)) {
      if (!step.group_name || !step.group_name.trim()) {
        patch.group_name = next === 'save_as_set' ? 'set1' : `${next}1`;
      }
      if (next === 'color' && !step.group_args?.color) {
        patch.group_args = { color: '#79c0ff' };
      }
    } else {
      patch.group_name = undefined;
      patch.group_args = undefined;
    }
    onChange(patch);
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8,
      paddingBottom: 8, borderBottom: '1px solid var(--bd)' }}>
      <span style={{ fontSize: 11, color: 'var(--txD)' }}>Then</span>
      <select value={verb} onChange={e => changeVerb(e.target.value)}
        style={{ ...SELECT, minWidth: 110 }}>
        <optgroup label="View">
          <option value="highlight">highlight</option>
          <option value="show_only">show only</option>
          <option value="hide">hide</option>
        </optgroup>
        <optgroup label="Group">
          <option value="tag">tag</option>
          <option value="color">color</option>
          <option value="cluster">cluster</option>
        </optgroup>
        <optgroup label="Data">
          <option value="save_as_set">save as set</option>
        </optgroup>
      </select>
      {needsGroup && (
        <input value={step.group_name || ''}
          onChange={e => onChange({ group_name: e.target.value })}
          placeholder="name" spellCheck={false}
          style={{ ...INPUT, maxWidth: 90, flex: 'none' }} />
      )}
      {verb === 'color' && (
        <input type="color" value={step.group_args?.color || '#79c0ff'}
          onChange={e => onChange({ group_args: { ...(step.group_args || {}), color: e.target.value } })}
          title="group colour"
          style={{ width: 26, height: 24, padding: 0, border: '1px solid var(--bd)',
            borderRadius: 'var(--rs)', background: 'var(--bgC)', cursor: 'pointer' }} />
      )}
    </div>
  );
}

export default function StepEditor({ step, schema, onChange, groupsRefreshKey }) {
  return (
    <div style={{ padding: 10, background: 'var(--bgP)', border: '1px solid var(--bd)',
      borderRadius: 6, marginTop: 8 }}>
      <VerbHeader step={step} onChange={onChange} />
      {step.kind === 'freehand'
        ? <FreehandEditor step={step} onChange={onChange} />
        : <VisualEditor step={step} schema={schema} onChange={onChange} groupsRefreshKey={groupsRefreshKey} />}
    </div>
  );
}
