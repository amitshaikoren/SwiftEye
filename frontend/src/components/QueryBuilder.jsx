/**
 * QueryBuilder — graph query panel with visual builder + freehand text.
 *
 * Two modes:
 *   - Visual: flat field dropdown, operator auto-adapts, value input
 *   - Freehand: text area accepting Cypher / SQL / PySpark syntax
 *
 * Both modes produce the same JSON contract and hit the same API.
 * Results are clickable — clicking a matched node/edge selects it on the graph.
 */
import React, { useState, useEffect, useMemo, useRef } from 'react';
import { runQuery, fetchQuerySchema, parseQueryText } from '../api';
import { EXAMPLES } from '../query/queryExamples';

// ── Operator sets per field type ────────────────────────────────────────

export const OPS_BY_TYPE = {
  numeric: [
    { op: '>', label: '>' }, { op: '<', label: '<' }, { op: '=', label: '=' },
    { op: '!=', label: '!=' }, { op: '>=', label: '>=' }, { op: '<=', label: '<=' },
  ],
  set: [
    { op: 'contains', label: 'contains' }, { op: 'contains_any', label: 'contains any' },
    { op: 'count_gt', label: 'count >' }, { op: 'count_lt', label: 'count <' }, { op: 'count_eq', label: 'count =' },
    { op: 'is_empty', label: 'is empty' }, { op: 'not_empty', label: 'not empty' },
  ],
  boolean: [
    { op: 'is_true', label: 'is true' }, { op: 'is_false', label: 'is false' },
  ],
  string: [
    { op: 'equals', label: 'equals' }, { op: 'starts_with', label: 'starts with' },
    { op: 'matches', label: 'matches (regex)' },
  ],
};

export const NO_VALUE_OPS = new Set(['is_empty', 'not_empty', 'is_true', 'is_false']);

// Field display name and grouping
function fieldLabel(name) {
  return name.replace(/_/g, ' ');
}

function groupFields(fields) {
  const groups = { Numeric: [], Sets: [], Flags: [], Text: [] };
  for (const [name, type] of Object.entries(fields)) {
    if (name === 'session_ids') continue;
    const entry = { name, label: fieldLabel(name), type };
    if (type === 'numeric') groups.Numeric.push(entry);
    else if (type === 'set') groups.Sets.push(entry);
    else if (type === 'boolean') groups.Flags.push(entry);
    else if (type === 'string') groups.Text.push(entry);
  }
  return groups;
}

// ── Syntax badge colors ─────────────────────────────────────────────────

const SYNTAX_COLORS = {
  cypher:  { bg: 'rgba(63,185,80,.12)', border: 'rgba(63,185,80,.3)', color: '#7ee787', label: 'Cypher' },
  sql:     { bg: 'rgba(88,166,255,.12)', border: 'rgba(88,166,255,.3)', color: '#79c0ff', label: 'SQL' },
  pyspark: { bg: 'rgba(240,136,62,.12)', border: 'rgba(240,136,62,.3)', color: '#f5a623', label: 'PySpark' },
};

// ── Schema reference (collapsible field list) ───────────────────────────

const TYPE_BADGE = {
  numeric: { color: '#79c0ff', bg: 'rgba(88,166,255,.1)' },
  set:     { color: '#d2a8ff', bg: 'rgba(210,168,255,.1)' },
  boolean: { color: '#7ee787', bg: 'rgba(63,185,80,.1)' },
  string:  { color: '#ffa657', bg: 'rgba(255,166,87,.1)' },
};

function fieldSyntax(name, dialect, entity) {
  // entity is 'n' for nodes, 'r' for edges
  if (dialect === 'cypher') return `${entity}.${name}`;
  if (dialect === 'pyspark') return `col("${name}")`;
  return name; // SQL
}

function SchemaReference({ schema, dialect }) {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState('nodes');

  const fields = tab === 'nodes' ? schema.node_fields : schema.edge_fields;
  const groups = groupFields(fields || {});
  const entity = tab === 'nodes' ? 'n' : 'r';
  const hasFields = Object.values(fields || {}).length > 0;

  return (
    <div style={{ marginTop: 2 }}>
      <button onClick={() => setOpen(!open)}
        style={{
          fontSize: 10, padding: '3px 10px', cursor: 'pointer',
          background: 'transparent', color: 'var(--txD)', border: '1px solid var(--bd)',
          borderRadius: 'var(--rs)',
        }}>
        Fields {open ? '▴' : '▾'}
      </button>

      {open && (
        <div style={{
          marginTop: 6, background: 'var(--bgP)', border: '1px solid var(--bd)',
          borderRadius: 8, padding: '8px 10px', maxHeight: 300, overflowY: 'auto',
        }}>
          {/* Node / Edge toggle */}
          <div style={{ display: 'flex', gap: 0, marginBottom: 8 }}>
            {['nodes', 'edges'].map((t, i) => (
              <button key={t} onClick={() => setTab(t)}
                style={{
                  fontSize: 9, padding: '3px 10px', cursor: 'pointer',
                  background: tab === t ? 'rgba(88,166,255,.12)' : 'transparent',
                  color: tab === t ? 'var(--ac)' : 'var(--txD)',
                  border: `1px solid ${tab === t ? 'var(--ac)' : 'var(--bd)'}`,
                  borderRadius: i === 0 ? 'var(--rs) 0 0 var(--rs)' : '0 var(--rs) var(--rs) 0',
                  fontWeight: tab === t ? 600 : 400,
                  borderLeft: i > 0 ? 'none' : undefined,
                }}>
                {t}
              </button>
            ))}
          </div>

          {!hasFields && (
            <div style={{ fontSize: 10, color: 'var(--txD)', padding: 4 }}>
              Load a capture to see available fields.
            </div>
          )}

          {Object.entries(groups).map(([group, entries]) =>
            entries.length > 0 && (
              <div key={group} style={{ marginBottom: 6 }}>
                <div style={{ fontSize: 9, color: 'var(--txD)', fontWeight: 600, marginBottom: 3, textTransform: 'uppercase', letterSpacing: '.05em' }}>
                  {group}
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                  {entries.map(f => (
                    <span key={f.name}
                      title={`${f.name} (${f.type})`}
                      style={{
                        fontSize: 10, fontFamily: 'var(--fn)', padding: '2px 6px', borderRadius: 4,
                        background: TYPE_BADGE[f.type]?.bg || 'var(--bgC)',
                        color: TYPE_BADGE[f.type]?.color || 'var(--txD)',
                        cursor: 'default', whiteSpace: 'nowrap',
                      }}>
                      {fieldSyntax(f.name, dialect, entity)}
                    </span>
                  ))}
                </div>
              </div>
            )
          )}
        </div>
      )}
    </div>
  );
}

// ── Component ───────────────────────────────────────────────────────────

export default function QueryBuilder({ loaded, onQueryResult, onClearQuery, onSelectNode, onSelectEdge, onAddStep }) {
  const [schema, setSchema] = useState({ node_fields: {}, edge_fields: {} });
  const [mode, setMode] = useState('freehand');  // 'visual' | 'freehand'

  // Visual mode state
  const [target, setTarget] = useState('nodes');
  const [conditions, setConditions] = useState([{ field: '', op: '', value: '' }]);
  const [logic, setLogic] = useState('AND');

  // Freehand mode state
  const [queryText, setQueryText] = useState('');
  const [dialect, setDialect] = useState('cypher');  // 'cypher' | 'sql' | 'pyspark'
  const [parseResult, setParseResult] = useState(null);
  const [showParseError, setShowParseError] = useState(false);
  const [showExamples, setShowExamples] = useState(false);

  // Shared state
  const [result, setResult] = useState(null);
  const [action, setAction] = useState('highlight');
  const [groupName, setGroupName] = useState('');
  const [groupColor, setGroupColor] = useState('#79c0ff');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Verbs that need a group identifier (tag/color/cluster/save_as_set).
  const ACTIONS_REQUIRE_GROUP = new Set(['tag', 'color', 'cluster', 'save_as_set']);
  const needsGroup = ACTIONS_REQUIRE_GROUP.has(action);

  // When the verb changes, reset group_name to a sensible default so "+ Add
  // step" is always pressable without extra clicks.
  function handleActionChange(next) {
    setAction(next);
    if (ACTIONS_REQUIRE_GROUP.has(next)) {
      setGroupName(prev => prev && !prev.startsWith('tag') && !prev.startsWith('color')
        && !prev.startsWith('cluster') && !prev.startsWith('set') ? prev : `${next === 'save_as_set' ? 'set' : next}1`);
    }
  }

  const parseTimer = useRef(null);
  const errorTimer = useRef(null);

  // Fetch schema on load
  useEffect(() => {
    if (!loaded) { setSchema({ node_fields: {}, edge_fields: {} }); return; }
    fetchQuerySchema().then(setSchema);
  }, [loaded]);

  const fields = target === 'nodes' ? schema.node_fields : schema.edge_fields;
  const fieldGroups = useMemo(() => groupFields(fields), [fields]);

  // Live parse freehand text via backend (debounced)
  // Parse result updates after 400ms of no typing.
  // Error display has an extra 600ms delay so it doesn't flash while typing.
  useEffect(() => {
    if (mode !== 'freehand' || !queryText.trim()) {
      setParseResult(null);
      setShowParseError(false);
      return;
    }
    // Hide error immediately on new keystrokes
    setShowParseError(false);
    clearTimeout(parseTimer.current);
    clearTimeout(errorTimer.current);
    parseTimer.current = setTimeout(() => {
      parseQueryText(queryText, dialect)
        .then(r => {
          setParseResult(r);
          // Delay showing errors so they don't flash during typing
          if (r?.error) {
            errorTimer.current = setTimeout(() => setShowParseError(true), 600);
          }
        })
        .catch(() => {
          setParseResult({ error: 'Parse request failed' });
          errorTimer.current = setTimeout(() => setShowParseError(true), 600);
        });
    }, 400);
    return () => { clearTimeout(parseTimer.current); clearTimeout(errorTimer.current); };
  }, [queryText, mode, dialect]);

  // ── Visual mode helpers ─────────────────────────────────────────────

  function getFieldType(fieldName) {
    return fields[fieldName] || 'string';
  }

  function updateCondition(idx, patch) {
    setConditions(prev => prev.map((c, i) => {
      if (i !== idx) return c;
      const next = { ...c, ...patch };
      // When field changes, reset op and value
      if (patch.field !== undefined && patch.field !== c.field) {
        const type = getFieldType(patch.field);
        const ops = OPS_BY_TYPE[type] || [];
        next.op = ops[0]?.op || '';
        next.value = '';
      }
      return next;
    }));
  }

  function addCondition() {
    setConditions(prev => [...prev, { field: '', op: '', value: '' }]);
  }

  function removeCondition(idx) {
    setConditions(prev => prev.length <= 1 ? prev : prev.filter((_, i) => i !== idx));
  }

  // ── Run query ───────────────────────────────────────────────────────

  async function handleRun() {
    let query;

    if (mode === 'freehand') {
      try {
        const parsed = await parseQueryText(queryText, dialect);
        if (parsed.error) { setError(parsed.error); return; }
        query = parsed.query;
      } catch (e) {
        setError('Failed to parse query: ' + e.message);
        return;
      }
    } else {
      // Visual mode
      const validConds = conditions
        .filter(c => c.field && c.op)
        .map(c => {
          const cond = { field: c.field, op: c.op };
          if (!NO_VALUE_OPS.has(c.op)) {
            const numVal = parseFloat(c.value);
            cond.value = isNaN(numVal) ? c.value : numVal;
          }
          return cond;
        });
      if (!validConds.length) return;
      query = { target, conditions: validConds, logic, action };
    }

    // Override action from the action selector; attach group metadata when needed.
    query.action = action;
    if (needsGroup) {
      if (!groupName.trim()) { setError('Enter a name for the ' + action + ' group.'); return; }
      query.group_name = groupName.trim();
      if (action === 'color') query.group_args = { color: groupColor };
    }

    setLoading(true); setError('');
    try {
      const res = await runQuery(query);
      setResult(res);
      if (onQueryResult) onQueryResult(res);
    } catch (e) {
      setError(e.message);
    }
    setLoading(false);
  }

  function handleClear() {
    setResult(null);
    setError('');
    setConditions([{ field: '', op: '', value: '' }]);
    setQueryText('');
    setParseResult(null);
    setShowParseError(false);
    if (onClearQuery) onClearQuery();
  }

  async function handleAddStep() {
    if (!onAddStep) return;
    const verb = action === 'select' ? 'highlight' : action;  // legacy alias
    if (needsGroup && !groupName.trim()) {
      setError('Enter a name for the ' + verb + ' group.'); return;
    }
    const groupFields = {};
    if (needsGroup) {
      groupFields.group_name = groupName.trim();
      if (verb === 'color') groupFields.group_args = { color: groupColor };
    }
    if (mode === 'freehand') {
      if (!queryText.trim()) { setError('Enter a query first.'); return; }
      let parsed = parseResult;
      if (!parsed || parsed.error || !parsed.query) {
        try {
          parsed = await parseQueryText(queryText, dialect);
        } catch (e) {
          setError('Parse request failed: ' + e.message); return;
        }
      }
      if (parsed?.error) { setError(parsed.error); return; }
      if (!parsed?.query) { setError('Could not parse query.'); return; }
      setError('');
      onAddStep({
        kind: 'freehand',
        verb,
        dialect,
        text: queryText,
        target: parsed.query.target || 'nodes',
        conditions: parsed.query.conditions || [],
        logic: parsed.query.logic || 'AND',
        ...groupFields,
      });
    } else {
      const validConds = conditions
        .filter(c => c.field && c.op)
        .map(c => {
          const out = { field: c.field, op: c.op };
          if (!NO_VALUE_OPS.has(c.op)) {
            const n = parseFloat(c.value);
            out.value = isNaN(n) ? c.value : n;
          }
          return out;
        });
      if (!validConds.length) { setError('Add at least one complete condition.'); return; }
      setError('');
      onAddStep({ kind: 'visual', verb, target, conditions: validConds, logic, ...groupFields });
    }
  }

  // ── Styles ──────────────────────────────────────────────────────────

  const selectStyle = {
    fontSize: 11, fontFamily: 'var(--fn)', padding: '5px 8px',
    background: 'var(--bgC)', color: 'var(--tx)', border: '1px solid var(--bd)',
    borderRadius: 'var(--rs)', outline: 'none', cursor: 'pointer',
  };

  const inputStyle = {
    fontSize: 11, fontFamily: 'var(--fn)', padding: '5px 8px',
    background: 'var(--bgC)', color: 'var(--tx)', border: '1px solid var(--bd)',
    borderRadius: 'var(--rs)', outline: 'none', flex: 1, minWidth: 60,
  };

  const hasFields = Object.keys(fields).length > 0;
  const syntaxInfo = SYNTAX_COLORS[dialect];

  return (
    <div style={{ overflowY: 'auto', padding: '16px 18px', background: 'var(--bg)', height: '100%' }}>

      {/* Header */}
      <div style={{ marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--tx)', fontFamily: 'var(--fd)' }}>
            Query
          </div>
          {result && (
            <span style={{ fontSize: 10, color: 'var(--ac)', fontFamily: 'var(--fn)' }}>
              {result.summary}
            </span>
          )}
        </div>
        <div style={{ fontSize: 10, color: 'var(--txD)' }}>
          Search the analysis graph with structured or freehand queries.
        </div>
      </div>

      {!loaded && (
        <div style={{ color: 'var(--txD)', fontSize: 11, marginTop: 30, textAlign: 'center' }}>
          No capture loaded.
        </div>
      )}

      {loaded && !hasFields && (
        <div style={{ color: 'var(--txD)', fontSize: 11, marginTop: 30, textAlign: 'center' }}>
          Loading schema...
        </div>
      )}

      {loaded && hasFields && (
        <>
          {/* Mode toggle */}
          <div style={{ display: 'flex', gap: 0, marginBottom: 12 }}>
            {['visual', 'freehand'].map(m => (
              <button key={m} onClick={() => setMode(m)}
                style={{
                  fontSize: 10, padding: '4px 14px', cursor: 'pointer',
                  background: mode === m ? 'var(--bgC)' : 'transparent',
                  color: mode === m ? 'var(--tx)' : 'var(--txD)',
                  border: '1px solid var(--bd)',
                  borderRadius: m === 'visual' ? 'var(--rs) 0 0 var(--rs)' : '0 var(--rs) var(--rs) 0',
                  fontWeight: mode === m ? 600 : 400,
                  borderLeft: m === 'freehand' ? 'none' : undefined,
                }}>
                {m === 'visual' ? 'Visual' : 'Freehand'}
              </button>
            ))}
          </div>

          {/* ── FREEHAND MODE ────────────────────────────────────────── */}
          {mode === 'freehand' && (
            <div>
              {/* Dialect selector */}
              <div style={{ display: 'flex', gap: 0, marginBottom: 8 }}>
                {[['cypher', 'Cypher'], ['sql', 'SQL'], ['pyspark', 'PySpark']].map(([d, label], i, arr) => (
                  <button key={d} onClick={() => setDialect(d)}
                    style={{
                      fontSize: 10, padding: '4px 12px', cursor: 'pointer',
                      background: dialect === d ? syntaxInfo?.bg || 'var(--bgC)' : 'transparent',
                      color: dialect === d ? (SYNTAX_COLORS[d]?.color || 'var(--tx)') : 'var(--txD)',
                      border: `1px solid ${dialect === d ? (SYNTAX_COLORS[d]?.border || 'var(--bd)') : 'var(--bd)'}`,
                      borderRadius: i === 0 ? 'var(--rs) 0 0 var(--rs)' : i === arr.length - 1 ? '0 var(--rs) var(--rs) 0' : '0',
                      fontWeight: dialect === d ? 600 : 400,
                      borderLeft: i > 0 ? 'none' : undefined,
                    }}>
                    {label}
                  </button>
                ))}
              </div>

              {/* Text area */}
              <textarea
                value={queryText}
                onChange={e => setQueryText(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) handleRun(); }}
                placeholder={dialect === 'cypher'
                  ? 'MATCH (n) WHERE n.packets > 1000 RETURN n'
                  : dialect === 'pyspark'
                  ? 'df.filter(col("packets") > 1000)'
                  : 'SELECT * FROM nodes WHERE packets > 1000'}
                spellCheck={false}
                style={{
                  width: '100%', minHeight: 70, maxHeight: 160, resize: 'vertical',
                  fontFamily: "'Cascadia Code', 'Fira Code', 'Consolas', monospace",
                  fontSize: 12, lineHeight: 1.6, padding: '10px 12px',
                  background: 'var(--bgP)', color: 'var(--tx)', border: '1px solid var(--bd)',
                  borderRadius: 8, outline: 'none', boxSizing: 'border-box',
                  marginBottom: 8,
                }}
              />

              {/* Parse error — only shown after typing stops (debounced) */}
              {showParseError && parseResult?.error && queryText.trim() && (
                <div style={{
                  fontSize: 10, color: '#f85149', padding: '6px 10px', marginBottom: 8,
                  background: 'rgba(248,81,73,.06)', border: '1px solid rgba(248,81,73,.15)',
                  borderRadius: 6, fontFamily: 'var(--fn)', whiteSpace: 'pre-wrap',
                }}>
                  {parseResult.error}
                </div>
              )}

              {/* Parse preview (live) */}
              {parseResult?.query && (
                <div style={{
                  fontSize: 10, color: 'var(--txD)', padding: '6px 10px', marginBottom: 8,
                  background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 6,
                  fontFamily: 'var(--fn)',
                }}>
                  {parseResult.query.target} · {parseResult.query.conditions.length} condition{parseResult.query.conditions.length !== 1 ? 's' : ''} · {parseResult.query.logic}
                </div>
              )}

              {/* Examples */}
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 10 }}>
                <div style={{ position: 'relative' }}>
                  <button onClick={() => setShowExamples(!showExamples)}
                    style={{
                      fontSize: 10, padding: '3px 10px', cursor: 'pointer',
                      background: 'transparent', color: 'var(--txD)', border: '1px solid var(--bd)',
                      borderRadius: 'var(--rs)',
                    }}>
                    Examples {showExamples ? '▴' : '▾'}
                  </button>
                  {showExamples && (
                    <div style={{
                      position: 'absolute', top: '100%', left: 0, zIndex: 20, marginTop: 4,
                      background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 8,
                      padding: '6px 0', minWidth: 340, maxHeight: 260, overflowY: 'auto',
                      boxShadow: '0 4px 16px rgba(0,0,0,.3)',
                    }}>
                      {EXAMPLES.map((ex, i) => {
                        const exText = ex[dialect] || ex.cypher;
                        return (
                          <div key={i}
                            onClick={() => { setQueryText(exText); setShowExamples(false); }}
                            style={{
                              padding: '6px 12px', cursor: 'pointer',
                              borderBottom: i < EXAMPLES.length - 1 ? '1px solid var(--bd)' : 'none',
                            }}
                            onMouseOver={e => e.currentTarget.style.background = 'rgba(255,255,255,.04)'}
                            onMouseOut={e => e.currentTarget.style.background = 'transparent'}
                          >
                            <div style={{ fontSize: 10, color: 'var(--txM)', fontWeight: 500, marginBottom: 2 }}>{ex.title}</div>
                            <div style={{ fontSize: 10, fontFamily: 'var(--fn)', color: 'var(--txD)' }}>{exText}</div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
                <span style={{ fontSize: 9, color: 'var(--txD)' }}>Ctrl+Enter to run</span>
              </div>

              {/* ── Field reference ─────────────────────────────────── */}
              <SchemaReference schema={schema} dialect={dialect} />
            </div>
          )}

          {/* ── VISUAL MODE ──────────────────────────────────────────── */}
          {mode === 'visual' && (
            <div>
              {/* Target row */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                <span style={{ fontSize: 11, color: 'var(--txD)' }}>Find</span>
                {['nodes', 'edges'].map(t => (
                  <button key={t}
                    onClick={() => { setTarget(t); setConditions([{ field: '', op: '', value: '' }]); setResult(null); }}
                    style={{
                      fontSize: 10, padding: '4px 12px', borderRadius: 'var(--rs)', cursor: 'pointer',
                      background: target === t ? 'rgba(88,166,255,.12)' : 'transparent',
                      color: target === t ? 'var(--ac)' : 'var(--txD)',
                      border: `1px solid ${target === t ? 'var(--ac)' : 'var(--bd)'}`,
                      fontWeight: target === t ? 600 : 400,
                    }}>
                    {t}
                  </button>
                ))}
                <span style={{ fontSize: 11, color: 'var(--txD)' }}>where</span>
                {conditions.length > 1 && (
                  <div style={{ display: 'flex', gap: 4, marginLeft: 'auto' }}>
                    {['AND', 'OR'].map(l => (
                      <button key={l} onClick={() => setLogic(l)}
                        style={{
                          fontSize: 9, padding: '3px 8px', borderRadius: 'var(--rs)', cursor: 'pointer',
                          background: logic === l ? 'rgba(88,166,255,.12)' : 'transparent',
                          color: logic === l ? 'var(--ac)' : 'var(--txD)',
                          border: `1px solid ${logic === l ? 'var(--ac)' : 'var(--bd)'}`,
                        }}>
                        {l}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Conditions */}
              {conditions.map((cond, idx) => {
                const type = cond.field ? getFieldType(cond.field) : null;
                const ops = type ? (OPS_BY_TYPE[type] || []) : [];
                const needsValue = cond.op && !NO_VALUE_OPS.has(cond.op);

                return (
                  <div key={idx} style={{
                    display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6,
                    padding: '7px 10px', background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 6,
                  }}>
                    {/* Field — flat with optgroups */}
                    <select value={cond.field}
                      onChange={e => updateCondition(idx, { field: e.target.value })}
                      style={{ ...selectStyle, minWidth: 100 }}>
                      <option value="">field...</option>
                      {Object.entries(fieldGroups).map(([group, items]) =>
                        items.length > 0 && (
                          <optgroup key={group} label={group}>
                            {items.map(f => (
                              <option key={f.name} value={f.name}>{f.label}</option>
                            ))}
                          </optgroup>
                        )
                      )}
                    </select>

                    {/* Operator */}
                    {cond.field && (
                      <select value={cond.op}
                        onChange={e => updateCondition(idx, { op: e.target.value })}
                        style={{ ...selectStyle, minWidth: 80 }}>
                        {ops.map(o => (
                          <option key={o.op} value={o.op}>{o.label}</option>
                        ))}
                      </select>
                    )}

                    {/* Value */}
                    {needsValue && (
                      <input type="text" value={cond.value} placeholder="value"
                        onChange={e => updateCondition(idx, { value: e.target.value })}
                        onKeyDown={e => e.key === 'Enter' && handleRun()}
                        style={inputStyle} />
                    )}

                    {/* Remove */}
                    {conditions.length > 1 && (
                      <button onClick={() => removeCondition(idx)}
                        style={{ fontSize: 13, color: 'var(--txD)', cursor: 'pointer', background: 'none', border: 'none', padding: '0 3px' }}>
                        &times;
                      </button>
                    )}
                  </div>
                );
              })}

              <button onClick={addCondition}
                style={{
                  fontSize: 10, padding: '3px 10px', cursor: 'pointer', marginBottom: 10,
                  background: 'transparent', color: 'var(--ac)', border: '1px solid var(--ac)',
                  borderRadius: 'var(--rs)',
                }}>
                + condition
              </button>
            </div>
          )}

          {/* ── Shared: Action + Run ───────────────────────────────────── */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '8px 0', borderTop: '1px solid var(--bd)', marginTop: 4,
          }}>
            <span style={{ fontSize: 10, color: 'var(--txD)' }}>Then</span>
            <select value={action} onChange={e => handleActionChange(e.target.value)}
              style={{ ...selectStyle, minWidth: 110 }}>
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
              <input value={groupName} onChange={e => setGroupName(e.target.value)}
                placeholder="name" spellCheck={false}
                style={{ ...inputStyle, maxWidth: 90, flex: 'none' }} />
            )}
            {action === 'color' && (
              <input type="color" value={groupColor} onChange={e => setGroupColor(e.target.value)}
                title="group colour"
                style={{ width: 26, height: 24, padding: 0, border: '1px solid var(--bd)',
                  borderRadius: 'var(--rs)', background: 'var(--bgC)', cursor: 'pointer' }} />
            )}
            <div style={{ flex: 1 }} />
            {result && (
              <button onClick={handleClear}
                style={{
                  fontSize: 10, padding: '5px 12px', cursor: 'pointer',
                  background: 'transparent', color: 'var(--txD)', border: '1px solid var(--bd)',
                  borderRadius: 'var(--rs)',
                }}>
                Clear
              </button>
            )}
            <button onClick={handleRun} disabled={loading}
              style={{
                fontSize: 10, padding: '5px 16px', cursor: 'pointer',
                background: 'rgba(63,185,80,.12)', color: '#7ee787',
                border: '1px solid rgba(63,185,80,.4)', borderRadius: 'var(--rs)',
                fontWeight: 600, opacity: loading ? 0.5 : 1,
              }}>
              {loading ? 'Running...' : 'Run'}
            </button>
            {onAddStep && (
              <button onClick={handleAddStep}
                title="Append this query as a step in the pipeline recipe below"
                style={{
                  fontSize: 10, padding: '5px 12px', cursor: 'pointer',
                  background: 'rgba(88,166,255,.12)', color: 'var(--ac)',
                  border: '1px solid rgba(88,166,255,.4)', borderRadius: 'var(--rs)',
                  fontWeight: 600,
                }}>
                + Add step
              </button>
            )}
          </div>

          {/* Error */}
          {error && (
            <div style={{
              fontSize: 10, color: '#f85149', marginTop: 8, padding: '6px 10px',
              background: 'rgba(248,81,73,.06)', border: '1px solid rgba(248,81,73,.15)',
              borderRadius: 6, whiteSpace: 'pre-wrap',
            }}>
              {error}
            </div>
          )}

          {/* ── Results ─────────────────────────────────────────────────── */}
          {result && result.total_matched > 0 && (
            <div style={{ marginTop: 12, background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 8, padding: '10px 12px' }}>
              <div style={{ fontSize: 11, color: 'var(--txM)', marginBottom: 8 }}>
                <span style={{ color: '#f0883e', fontWeight: 700, fontSize: 14 }}>{result.total_matched}</span>
                <span style={{ color: 'var(--txD)' }}> / {result.total_searched} matched</span>
              </div>

              {/* Matched nodes — clickable */}
              {result.matched_nodes?.length > 0 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                  {result.matched_nodes.map(m => (
                    <div key={m.id}
                      onClick={() => onSelectNode && onSelectNode(m.id)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 8,
                        fontSize: 11, fontFamily: 'var(--fn)', padding: '4px 8px', borderRadius: 4,
                        cursor: onSelectNode ? 'pointer' : 'default',
                        background: 'rgba(240,136,62,.06)', border: '1px solid rgba(240,136,62,.15)',
                      }}
                      onMouseOver={e => e.currentTarget.style.background = 'rgba(240,136,62,.12)'}
                      onMouseOut={e => e.currentTarget.style.background = 'rgba(240,136,62,.06)'}
                    >
                      <span style={{ color: '#f0883e', fontWeight: 500 }}>{m.id}</span>
                      {m.match_details && Object.entries(m.match_details).slice(0, 2).map(([k, v]) => (
                        <span key={k} style={{
                          fontSize: 9, color: 'var(--txD)', padding: '1px 6px',
                          background: 'var(--bgC)', borderRadius: 3,
                        }}>
                          {fieldLabel(k)}: {Array.isArray(v) ? v.slice(0, 3).join(', ') : String(v)}
                        </span>
                      ))}
                    </div>
                  ))}
                </div>
              )}

              {/* Matched edges — clickable */}
              {result.matched_edges?.length > 0 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 3, marginTop: result.matched_nodes?.length ? 6 : 0 }}>
                  {result.matched_edges.map(m => (
                    <div key={m.id}
                      onClick={() => onSelectEdge && onSelectEdge(m.id)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 8,
                        fontSize: 11, fontFamily: 'var(--fn)', padding: '4px 8px', borderRadius: 4,
                        cursor: onSelectEdge ? 'pointer' : 'default',
                        background: 'rgba(240,136,62,.06)', border: '1px solid rgba(240,136,62,.15)',
                      }}
                      onMouseOver={e => e.currentTarget.style.background = 'rgba(240,136,62,.12)'}
                      onMouseOut={e => e.currentTarget.style.background = 'rgba(240,136,62,.06)'}
                    >
                      <span style={{ color: '#f0883e', fontWeight: 500 }}>{m.source}</span>
                      <span style={{ color: 'var(--txD)', fontSize: 9 }}>&harr;</span>
                      <span style={{ color: '#f0883e', fontWeight: 500 }}>{m.target}</span>
                      {m.match_details && Object.entries(m.match_details).slice(0, 2).map(([k, v]) => (
                        <span key={k} style={{
                          fontSize: 9, color: 'var(--txD)', padding: '1px 6px',
                          background: 'var(--bgC)', borderRadius: 3,
                        }}>
                          {fieldLabel(k)}: {Array.isArray(v) ? v.slice(0, 3).join(', ') : String(v)}
                        </span>
                      ))}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {result && result.total_matched === 0 && (
            <div style={{
              marginTop: 12, padding: '10px 12px', textAlign: 'center',
              background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 8,
              color: 'var(--txD)', fontSize: 11,
            }}>
              No matches.
            </div>
          )}
        </>
      )}
    </div>
  );
}
