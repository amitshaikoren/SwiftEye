/**
 * EventFlagModal — "Flag as Event" dialog (v0.21.0).
 *
 * Renders a centered modal over the app for creating a new researcher Event
 * from a node, edge, or session. Pre-fills title from the entity, lets the
 * researcher pick severity + write a short description, optionally snapshots
 * the entity's existing annotation text into the Event.
 *
 * Wired up by App.jsx which owns the open/close state. The actual creation
 * is delegated to `c.addEvent` (from useEvents in useCapture).
 */
import React, { useState, useEffect, useMemo } from 'react';

const SEVERITIES = [
  { value: null,       label: 'None',     color: '#8b949e' },
  { value: 'info',     label: 'Info',     color: '#8b949e' },
  { value: 'low',      label: 'Low',      color: '#58a6ff' },
  { value: 'medium',   label: 'Medium',   color: '#d29922' },
  { value: 'high',     label: 'High',     color: '#f0883e' },
  { value: 'critical', label: 'Critical', color: '#f85149' },
];

// d3 force simulation replaces string source/target with node objects.
// This helper extracts the plain ID regardless of which form we have.
function resolveId(ref) {
  if (ref == null) return '';
  if (typeof ref === 'string') return ref;
  return ref.id ?? String(ref);
}

function defaultTitle(entity_type, entity) {
  if (!entity) return '';
  if (entity_type === 'node') return entity.id || 'Node';
  if (entity_type === 'edge') {
    const src = resolveId(entity.source);
    const tgt = resolveId(entity.target);
    return `${src} → ${tgt}`;
  }
  if (entity_type === 'session') {
    const src = entity.src_ip || entity.initiator_ip || '';
    const tgt = entity.dst_ip || entity.responder_ip || '';
    const proto = entity.protocol || (entity.protocols || []).join('/');
    return proto ? `${src} --${proto}→ ${tgt}` : `${src} → ${tgt}`;
  }
  return '';
}

export default function EventFlagModal({
  open,
  entity,
  entity_type,
  graph,                 // current graph (used by useEvents to derive node first_seen)
  existingAnnotation,    // optional: text to offer as snapshot
  onConfirm,             // ({ title, severity, description, includeAnnotation }) => void
  onClose,
}) {
  const [title, setTitle]                   = useState('');
  const [severity, setSeverity]             = useState('medium');
  const [description, setDescription]       = useState('');
  const [includeAnnotation, setIncludeAnnotation] = useState(true);

  // Reset form whenever a new entity is opened.
  useEffect(() => {
    if (!open) return;
    setTitle(defaultTitle(entity_type, entity));
    setSeverity('medium');
    setDescription('');
    setIncludeAnnotation(!!existingAnnotation);
  }, [open, entity, entity_type, existingAnnotation]);

  const targetSummary = useMemo(() => {
    if (!entity) return '';
    if (entity_type === 'node') return `Node · ${entity.id}`;
    if (entity_type === 'edge') {
      const src = resolveId(entity.source);
      const tgt = resolveId(entity.target);
      const proto = entity.protocol || (entity.protocols || []).join(', ');
      return `Edge · ${src} → ${tgt}${proto ? ' · ' + proto : ''}`;
    }
    if (entity_type === 'session') {
      const src = entity.src_ip || entity.initiator_ip || '';
      const tgt = entity.dst_ip || entity.responder_ip || '';
      const proto = entity.protocol || (entity.protocols || []).join('/');
      return `Session · ${src}${proto ? ' --' + proto + '→' : ' →'} ${tgt}`;
    }
    return '';
  }, [entity, entity_type]);

  if (!open || !entity || !entity_type) return null;

  function handleSubmit(e) {
    e?.preventDefault?.();
    const finalTitle = title.trim() || defaultTitle(entity_type, entity);
    onConfirm?.({
      title: finalTitle,
      severity,
      description: description.trim(),
      includeAnnotation,
    });
  }

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0, zIndex: 9000,
          background: 'rgba(0,0,0,.55)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}
      >
        {/* Dialog */}
        <form
          onClick={e => e.stopPropagation()}
          onSubmit={handleSubmit}
          style={{
            background: 'var(--bgP)',
            border: '1px solid var(--bd)',
            borderRadius: 8,
            boxShadow: '0 20px 60px rgba(0,0,0,.6)',
            width: 460,
            maxWidth: '92vw',
            display: 'flex', flexDirection: 'column',
            overflow: 'hidden',
          }}
        >
          {/* Header */}
          <div style={{
            padding: '10px 14px', borderBottom: '1px solid var(--bd)',
            display: 'flex', alignItems: 'center', gap: 8,
            background: 'var(--bgH)',
          }}>
            <div style={{
              width: 8, height: 8, borderRadius: '50%',
              background: SEVERITIES.find(s => s.value === severity)?.color || '#8b949e',
            }} />
            <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--tx)', fontFamily: 'var(--fd)' }}>
              Flag as Event
            </div>
            <div style={{ flex: 1 }} />
            <button type="button" className="btn"
              onClick={onClose}
              style={{ fontSize: 9, padding: '2px 8px' }}>Cancel</button>
          </div>

          {/* Target summary */}
          <div style={{
            padding: '8px 14px', fontSize: 10, color: 'var(--txD)',
            borderBottom: '1px solid var(--bd)', fontFamily: 'var(--fn)',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>
            {targetSummary}
          </div>

          {/* Body */}
          <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>

            {/* Title */}
            <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <span style={{ fontSize: 9, color: 'var(--txD)', fontWeight: 600, letterSpacing: 0.5 }}>TITLE</span>
              <input
                value={title}
                onChange={e => setTitle(e.target.value)}
                autoFocus
                placeholder="e.g. ARP Spoof origin"
                style={{
                  background: 'var(--bg)', border: '1px solid var(--bd)',
                  borderRadius: 4, padding: '6px 8px',
                  fontSize: 12, color: 'var(--tx)', fontFamily: 'var(--fn)',
                  outline: 'none',
                }}
              />
            </label>

            {/* Severity */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <span style={{ fontSize: 9, color: 'var(--txD)', fontWeight: 600, letterSpacing: 0.5 }}>SEVERITY</span>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {SEVERITIES.map(s => {
                  const active = severity === s.value;
                  return (
                    <button
                      key={s.label}
                      type="button"
                      onClick={() => setSeverity(s.value)}
                      style={{
                        background: active ? s.color : 'var(--bg)',
                        border: `1px solid ${active ? s.color : 'var(--bd)'}`,
                        color: active ? '#000' : s.color,
                        borderRadius: 4, padding: '3px 10px',
                        fontSize: 10, fontWeight: 600,
                        fontFamily: 'var(--fn)', cursor: 'pointer',
                      }}
                    >
                      {s.label}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Description */}
            <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <span style={{ fontSize: 9, color: 'var(--txD)', fontWeight: 600, letterSpacing: 0.5 }}>NOTES (optional)</span>
              <textarea
                value={description}
                onChange={e => setDescription(e.target.value)}
                placeholder="What did you notice? Why is this interesting?"
                rows={4}
                style={{
                  background: 'var(--bg)', border: '1px solid var(--bd)',
                  borderRadius: 4, padding: '6px 8px',
                  fontSize: 11, color: 'var(--tx)', fontFamily: 'var(--fn)',
                  outline: 'none', resize: 'vertical', minHeight: 60,
                  lineHeight: 1.5,
                }}
              />
            </label>

            {/* Annotation snapshot toggle */}
            {existingAnnotation && (
              <label style={{
                display: 'flex', alignItems: 'center', gap: 6,
                fontSize: 11, color: 'var(--txM)', cursor: 'pointer',
                background: 'var(--bg)', border: '1px solid var(--bd)',
                borderRadius: 4, padding: '6px 8px',
              }}>
                <input
                  type="checkbox"
                  checked={includeAnnotation}
                  onChange={e => setIncludeAnnotation(e.target.checked)}
                />
                <span>Include current annotation: <i style={{ color: 'var(--txD)' }}>"{existingAnnotation.slice(0, 60)}{existingAnnotation.length > 60 ? '…' : ''}"</i></span>
              </label>
            )}
          </div>

          {/* Footer */}
          <div style={{
            padding: '10px 14px', borderTop: '1px solid var(--bd)',
            background: 'var(--bgH)',
            display: 'flex', justifyContent: 'flex-end', gap: 6,
          }}>
            <button type="button" className="btn"
              onClick={onClose}
              style={{ fontSize: 10, padding: '4px 10px' }}>Cancel</button>
            <button type="submit" className="btn on"
              style={{ fontSize: 10, padding: '4px 14px' }}>Flag Event</button>
          </div>
        </form>
      </div>
    </>
  );
}
