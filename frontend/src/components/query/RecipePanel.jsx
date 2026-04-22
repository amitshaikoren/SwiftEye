/**
 * RecipePanel — the pipeline UI shown below QueryBuilder in the query panel.
 *
 * Wraps Recipe (ordered sortable steps) + an output metrics block. Auto-runs
 * POST /api/query/pipeline on every steps change (debounced), feeds
 * highlighted ids upward via `onHighlightChange`.
 *
 * State ownership: the `steps` array lives in AppRightPanel (hoisted + persisted
 * to localStorage) so navigating to other right panels and back keeps it intact.
 */
import React, { useEffect, useRef, useState } from 'react';
import { fetchQuerySchema, runQueryPipeline } from '../../api';
import Recipe from './Recipe';

const RECIPE_HEIGHT_KEY = 'swifteye.recipePanel.recipeHeight';
const RECIPE_HEIGHT_MIN = 120;
const RECIPE_HEIGHT_MAX = 900;
const RECIPE_HEIGHT_DEFAULT = 340;

function stepIsRunnable(step) {
  if (step.enabled === false) return false;
  const conds = (step.conditions || []).filter(c => c.field && c.op);
  // A from_group step with no conditions still has a well-defined candidate
  // set (the group members), so treat it as runnable.
  return conds.length > 0 || !!step.from_group;
}

function stepToPayload(step) {
  const conds = (step.conditions || []).filter(c => c.field && c.op).map(c => {
    const out = { field: c.field, op: c.op };
    if (c.value !== undefined && c.value !== '') {
      const n = parseFloat(c.value);
      out.value = isNaN(n) ? c.value : n;
    }
    return out;
  });
  const payload = {
    verb: step.verb || 'highlight',
    target: step.target || 'nodes',
    conditions: conds,
    logic: step.logic || 'AND',
    enabled: step.enabled !== false,
  };
  if (step.group_name) payload.group_name = step.group_name;
  if (step.group_args) payload.group_args = step.group_args;
  if (step.from_group && step.from_group.kind && step.from_group.name) {
    payload.from_group = { kind: step.from_group.kind, name: step.from_group.name };
  }
  return payload;
}

export default function RecipePanel({ loaded, steps, onStepsChange, onHighlightChange, onHiddenChange, onColorChange, onTagChange, onRunComplete, groupsRefreshKey }) {
  const [schema, setSchema] = useState({ node_fields: {}, edge_fields: {} });
  const [envelope, setEnvelope] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const runTimer = useRef(null);
  const lastSigRef = useRef('');
  const [recipeHeight, setRecipeHeight] = useState(() => {
    const raw = typeof window !== 'undefined' && window.localStorage?.getItem(RECIPE_HEIGHT_KEY);
    const n = raw ? parseInt(raw, 10) : NaN;
    return Number.isFinite(n) ? Math.max(RECIPE_HEIGHT_MIN, Math.min(RECIPE_HEIGHT_MAX, n)) : RECIPE_HEIGHT_DEFAULT;
  });
  const heightRef = useRef(recipeHeight);
  heightRef.current = recipeHeight;
  // Recipe only clears graph state it previously set, so a one-shot Run from
  // QueryBuilder isn't wiped when the recipe has zero runnable steps.
  const ownedRef = useRef(false);
  const ownedExtrasRef = useRef(false);

  useEffect(() => {
    if (!loaded) { setSchema({ node_fields: {}, edge_fields: {} }); return; }
    fetchQuerySchema().then(setSchema);
  }, [loaded]);

  useEffect(() => {
    clearTimeout(runTimer.current);
    const runnable = steps.filter(stepIsRunnable);
    if (!runnable.length) {
      setEnvelope(null);
      lastSigRef.current = '';
      if (ownedRef.current && onHighlightChange) {
        onHighlightChange(null);
        ownedRef.current = false;
      }
      if (ownedExtrasRef.current) {
        if (onHiddenChange) onHiddenChange(new Set());
        if (onColorChange) onColorChange({});
        if (onTagChange) onTagChange({});
        ownedExtrasRef.current = false;
      }
      return;
    }
    // Signature to skip redundant runs (e.g. reorder with no runnable change)
    const sig = JSON.stringify(runnable.map(stepToPayload));
    if (sig === lastSigRef.current) return;
    runTimer.current = setTimeout(async () => {
      setLoading(true); setError('');
      try {
        const payload = runnable.map(stepToPayload);
        const res = await runQueryPipeline(payload);
        setEnvelope(res);
        lastSigRef.current = sig;
        const nodes = new Set();
        const edges = new Set();
        for (const h of (res.highlights || [])) {
          const bucket = h.target === 'edges' ? edges : nodes;
          for (const id of (h.ids || [])) bucket.add(id);
        }
        if (onHighlightChange) {
          onHighlightChange(nodes.size || edges.size ? { nodes, edges } : null);
          ownedRef.current = true;
        }
        // Hide/show_only → drive graph hidden-node state
        if (onHiddenChange) {
          onHiddenChange(new Set(res.hidden?.nodes || []));
          ownedExtrasRef.current = true;
        }
        // Color verb → per-node color overrides
        if (onColorChange) {
          const colorMap = {};
          for (const [, entry] of Object.entries(res.groups?.color || {})) {
            const color = entry.args?.color;
            if (color && entry.target === 'nodes') {
              for (const id of (entry.members || [])) colorMap[id] = color;
            }
          }
          onColorChange(colorMap);
          ownedExtrasRef.current = true;
        }
        // Tag verb → node tag badge overlays
        if (onTagChange) {
          const tagMap = {};
          for (const [tagName, entry] of Object.entries(res.groups?.tag || {})) {
            if (entry.target === 'nodes') {
              for (const id of (entry.members || [])) {
                if (!tagMap[id]) tagMap[id] = [];
                tagMap[id].push(tagName);
              }
            }
          }
          onTagChange(tagMap);
          ownedExtrasRef.current = true;
        }
        if (onRunComplete) onRunComplete();
      } catch (e) {
        setError(e.message || 'Pipeline run failed');
      }
      setLoading(false);
    }, 300);
    return () => clearTimeout(runTimer.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [steps]);

  function startDrag(e) {
    e.preventDefault();
    const startY = e.clientY;
    const startH = heightRef.current;
    function onMove(ev) {
      const h = Math.max(RECIPE_HEIGHT_MIN, Math.min(RECIPE_HEIGHT_MAX, startH + (ev.clientY - startY)));
      setRecipeHeight(h);
    }
    function onUp() {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
      try { window.localStorage?.setItem(RECIPE_HEIGHT_KEY, String(heightRef.current)); } catch {}
    }
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  }

  return (
    <div style={{ padding: '14px 18px 0', borderTop: '1px solid var(--bd)' }}>
      <div style={{ height: recipeHeight, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
        <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 8, flexShrink: 0 }}>
          <h2 style={sectionLabel}>Recipe</h2>
          {steps.length > 0 && (
            <button onClick={() => onStepsChange([])}
              style={{
                fontSize: 10, padding: '3px 10px', cursor: 'pointer',
                background: 'transparent', color: 'var(--txD)',
                border: '1px solid var(--bd)', borderRadius: 'var(--rs)',
              }}>Clear all</button>
          )}
        </div>

        <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', paddingRight: 2 }}>
          <Recipe steps={steps} onStepsChange={onStepsChange} schema={schema} groupsRefreshKey={groupsRefreshKey} />

          {error && (
            <div style={{
              marginTop: 10, fontSize: 10, color: '#f85149', padding: '6px 10px',
              background: 'rgba(248,81,73,.06)', border: '1px solid rgba(248,81,73,.15)',
              borderRadius: 6,
            }}>{error}</div>
          )}
        </div>
      </div>

      <div
        onMouseDown={startDrag}
        title="Drag to resize"
        style={{
          height: 6, margin: '4px -18px 4px', cursor: 'row-resize',
          background: 'var(--bd)', opacity: 0.35,
        }}
        onMouseEnter={e => (e.currentTarget.style.opacity = '0.7')}
        onMouseLeave={e => (e.currentTarget.style.opacity = '0.35')}
      />

      <div style={{ paddingBottom: 14 }}>
      {/* Output */}
      <h2 style={{ ...sectionLabel, marginTop: 4 }}>Output</h2>
      {envelope ? (
        <div style={{ background: 'var(--bgP)', border: '1px solid var(--bd)',
          borderRadius: 6, padding: '8px 12px' }}>
          <Metric label="Visible nodes" value={(envelope.visible?.nodes || []).length} />
          <Metric label="Visible edges" value={(envelope.visible?.edges || []).length} />
          <Metric label="Hidden nodes" value={(envelope.hidden?.nodes || []).length} dim />
          <Metric label="Highlighted"
            value={(envelope.highlights || []).reduce((n, h) => n + (h.ids?.length || 0), 0)} />
          {Object.keys(envelope.groups?.tag || {}).length > 0 && (
            <Metric label="Tags" value={Object.keys(envelope.groups.tag).length} />
          )}
          {Object.keys(envelope.groups?.color || {}).length > 0 && (
            <Metric label="Coloured" value={Object.keys(envelope.groups.color).length} />
          )}
          {Object.keys(envelope.groups?.cluster || {}).length > 0 && (
            <Metric label="Clusters" value={Object.keys(envelope.groups.cluster).length} />
          )}
          {Object.keys(envelope.saved_sets || {}).length > 0 && (
            <div style={{ marginTop: 8, paddingTop: 6, borderTop: '1px solid var(--bd)' }}>
              <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 4 }}>Saved sets</div>
              {Object.entries(envelope.saved_sets).map(([name, info]) => (
                <div key={name} style={{ display: 'flex', justifyContent: 'space-between',
                  fontSize: 11, padding: '2px 0' }}>
                  <span style={{ fontFamily: 'var(--fn)', color: '#d2a8ff' }}>@{name}</span>
                  <span style={{ color: 'var(--txD)' }}>
                    {(info.members || []).length} {info.target || 'nodes'}
                  </span>
                </div>
              ))}
            </div>
          )}
          {(envelope.warnings || []).length > 0 && (
            <div style={{ marginTop: 8, fontSize: 10, color: '#e3b341' }}>
              {envelope.warnings.map((w, i) => <div key={i}>⚠ {w}</div>)}
            </div>
          )}
        </div>
      ) : (
        <div style={{ fontSize: 10, color: 'var(--txD)', padding: '6px 2px' }}>
          {loading ? 'Running...' : steps.length === 0
            ? 'No steps yet.'
            : 'Complete or enable at least one step to see output.'}
        </div>
      )}
      </div>
    </div>
  );
}

function Metric({ label, value, dim }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '3px 0', fontSize: 11 }}>
      <span style={{ color: 'var(--txD)' }}>{label}</span>
      <span style={{ fontFamily: 'var(--fn)', color: dim ? '#f85149' : '#7ee787' }}>{value}</span>
    </div>
  );
}

const sectionLabel = {
  fontSize: 11, margin: 0, color: 'var(--txD)',
  textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600,
};
