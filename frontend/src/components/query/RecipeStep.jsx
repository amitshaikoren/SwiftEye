/**
 * RecipeStep — one step card in the recipe.
 *
 * Handles both visual (target + conditions summary) and freehand (dialect
 * badge + truncated query text) step kinds. Sortable via dnd-kit.
 */
import React from 'react';
import { useSortable } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import StepEditor from './StepEditor';

const VERB_STYLE = {
  highlight: { bg: 'rgba(121,192,255,.12)', color: '#79c0ff', label: 'Highlight' },
  show_only: { bg: 'rgba(121,192,255,.12)', color: '#79c0ff', label: 'Show only' },
  hide:      { bg: 'rgba(121,192,255,.12)', color: '#79c0ff', label: 'Hide' },
  tag:       { bg: 'rgba(126,231,135,.12)', color: '#7ee787', label: 'Tag' },
  color:     { bg: 'rgba(126,231,135,.12)', color: '#7ee787', label: 'Color' },
  cluster:   { bg: 'rgba(126,231,135,.12)', color: '#7ee787', label: 'Cluster' },
  save_as_set: { bg: 'rgba(210,168,255,.12)', color: '#d2a8ff', label: 'Save as set' },
};

const DIALECT_COLOR = {
  cypher:  '#7ee787',
  sql:     '#79c0ff',
  pyspark: '#f5a623',
};

function VisualSummary({ step }) {
  const c = (step.conditions || []).filter(x => x.field && x.op);
  if (!c.length) return <span style={{ color: 'var(--txD)', fontStyle: 'italic' }}>no conditions</span>;
  const parts = c.map(x => {
    const v = x.value !== undefined && x.value !== '' ? ` ${x.value}` : '';
    return `${x.field} ${x.op}${v}`;
  });
  return <span style={{ fontFamily: 'var(--fn)', fontSize: 11, color: 'var(--tx)' }}>
    {parts.join(` ${step.logic || 'AND'} `)}
  </span>;
}

function FreehandSummary({ step }) {
  const t = (step.text || '').replace(/\s+/g, ' ').trim();
  const truncated = t.length > 80 ? t.slice(0, 78) + '…' : t;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
      <span style={{
        fontSize: 9, padding: '1px 6px', borderRadius: 3, fontFamily: 'var(--fn)',
        color: DIALECT_COLOR[step.dialect] || 'var(--txD)',
        border: `1px solid ${DIALECT_COLOR[step.dialect] || 'var(--bd)'}40`,
      }}>{step.dialect}</span>
      <span style={{ fontFamily: 'var(--fn)', fontSize: 11, color: 'var(--tx)',
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {truncated || <em style={{ color: 'var(--txD)' }}>empty</em>}
      </span>
    </span>
  );
}

function GroupBadge({ step }) {
  if (!step.group_name) return null;
  const color = step.verb === 'color' ? step.group_args?.color : null;
  return (
    <span style={{
      marginLeft: 8, display: 'inline-flex', alignItems: 'center', gap: 4,
      fontSize: 10, fontFamily: 'var(--fn)', color: '#d2a8ff',
    }}>
      <span style={{ color: 'var(--txD)' }}>→</span>
      {color && (
        <span style={{ width: 10, height: 10, background: color, borderRadius: 2,
          border: '1px solid var(--bd)', display: 'inline-block' }} />
      )}
      @{step.group_name}
    </span>
  );
}

export default function RecipeStep({ step, index, editing, onToggleEdit, onPatch, onToggleEnabled, onRemove, schema }) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id: step.id });
  const vs = VERB_STYLE[step.verb] || VERB_STYLE.highlight;

  const wrapStyle = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: step.enabled === false ? 0.4 : (isDragging ? 0.6 : 1),
    background: 'var(--bg)',
    border: '1px solid var(--bd)',
    borderRadius: 5,
    padding: '8px 10px',
    marginBottom: 6,
    fontSize: 12,
  };

  return (
    <div ref={setNodeRef} style={wrapStyle}>
      <div style={{ display: 'grid', gridTemplateColumns: '14px 20px 70px 1fr auto', gap: 8, alignItems: 'center', minWidth: 0 }}>
        <span {...attributes} {...listeners}
          style={{ color: 'var(--txD)', cursor: 'grab', fontFamily: 'var(--fn)', userSelect: 'none' }}
          title="drag to reorder">⋮⋮</span>
        <span style={{ color: 'var(--txD)', fontFamily: 'var(--fn)', fontWeight: 600 }}>{index + 1}</span>
        <span style={{
          fontFamily: 'var(--fn)', fontWeight: 600, fontSize: 10,
          padding: '2px 7px', borderRadius: 3, textAlign: 'center',
          background: vs.bg, color: vs.color,
        }}>{vs.label}</span>
        <span style={{ minWidth: 0, overflow: 'hidden' }}>
          <span style={{
            display: 'inline-block', padding: '1px 6px', marginRight: 6,
            background: 'var(--bgC)', border: '1px solid var(--bd)', borderRadius: 10,
            fontSize: 10, color: 'var(--txD)',
          }}>{step.target || 'nodes'}</span>
          {step.kind === 'freehand'
            ? <FreehandSummary step={step} />
            : <VisualSummary step={step} />}
          <GroupBadge step={step} />
        </span>
        <span style={{ display: 'inline-flex', gap: 4 }}>
          <button onClick={onToggleEnabled} title={step.enabled === false ? 'enable' : 'disable'}
            style={iconBtnStyle}>{step.enabled === false ? '○' : '●'}</button>
          <button onClick={onToggleEdit} title="edit"
            style={{ ...iconBtnStyle, color: editing ? 'var(--ac)' : 'var(--txD)' }}>✎</button>
          <button onClick={onRemove} title="remove"
            style={{ ...iconBtnStyle, color: '#f85149' }}>✕</button>
        </span>
      </div>
      {editing && <StepEditor step={step} schema={schema} onChange={onPatch} />}
    </div>
  );
}

const iconBtnStyle = {
  width: 22, height: 22, display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
  background: 'transparent', border: 0, color: 'var(--txD)', cursor: 'pointer', borderRadius: 3, fontSize: 12,
};
