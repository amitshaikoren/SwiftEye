import React from 'react';

export default function GraphAnnotationOverlay({
  annotations, tRef, nRef, eRef, transformVersion,
  editingAnn, setEditingAnn, onUpdateAnnotation, onDeleteAnnotation,
}) {
  const t = tRef.current;

  return annotations.map(ann => {
    let sx, sy;
    if (ann.node_id) {
      const node = nRef.current.find(n => n.id === ann.node_id);
      if (!node) return null;
      sx = node.x * t.k + t.x;
      sy = (node.y - 30) * t.k + t.y;
    } else if (ann.edge_id) {
      const edge = eRef.current.find(e => e.id === ann.edge_id);
      if (!edge) return null;
      const src = typeof edge.source === 'object' ? edge.source : nRef.current.find(n => n.id === edge.source);
      const tgt = typeof edge.target === 'object' ? edge.target : nRef.current.find(n => n.id === edge.target);
      if (!src || !tgt) return null;
      sx = ((src.x + tgt.x) / 2) * t.k + t.x;
      sy = ((src.y + tgt.y) / 2 - 20) * t.k + t.y;
    } else {
      sx = ann.x * t.k + t.x;
      sy = ann.y * t.k + t.y;
    }
    return (
      <div key={ann.id} style={{
        position: 'absolute', left: sx, top: sy, zIndex: 50,
        transform: 'translate(-50%, -100%)',
        pointerEvents: 'auto',
      }}>
        {editingAnn === ann.id ? (
          <input
            autoFocus
            defaultValue={ann.label}
            onBlur={e => {
              const val = e.target.value.trim();
              if (val) onUpdateAnnotation?.(ann.id, { label: val });
              else onDeleteAnnotation?.(ann.id);
              setEditingAnn(null);
            }}
            onKeyDown={e => {
              if (e.key === 'Enter') e.target.blur();
              if (e.key === 'Escape') { setEditingAnn(null); }
            }}
            style={{
              background: 'var(--bgP)', border: `1px solid ${ann.color}`,
              borderRadius: 4, padding: '2px 6px',
              fontSize: Math.round(Math.max(8, Math.min(16, 11 * t.k))),
              color: 'var(--tx)', fontFamily: 'var(--fn)', outline: 'none',
              minWidth: 80,
            }}
          />
        ) : (
          <div
            onDoubleClick={() => setEditingAnn(ann.id)}
            style={{
              background: 'var(--bgP)', border: `1px solid ${ann.color}`,
              borderRadius: 4, padding: '2px 8px',
              fontSize: Math.round(Math.max(8, Math.min(16, 11 * t.k))),
              color: ann.color, fontFamily: 'var(--fn)',
              cursor: 'pointer', whiteSpace: 'nowrap',
              boxShadow: '0 2px 6px rgba(0,0,0,.3)',
              display: 'flex', alignItems: 'center', gap: 5,
            }}
          >
            {ann.node_id && <span style={{ fontSize: 8, opacity: 0.6 }}>&#x2B24; </span>}
            {ann.edge_id && <span style={{ fontSize: 8, opacity: 0.6 }}>&mdash; </span>}
            {ann.label}
            <span
              onClick={e => { e.stopPropagation(); onDeleteAnnotation?.(ann.id); }}
              style={{ color: 'var(--txD)', fontSize: 9, cursor: 'pointer', marginLeft: 2 }}
            >&#x2715;</span>
          </div>
        )}
        {/* Pin line — only for canvas annotations */}
        {!ann.node_id && !ann.edge_id && (
          <div style={{
            position: 'absolute', left: '50%', top: '100%',
            width: 1, height: 8, background: ann.color, opacity: 0.6,
            transform: 'translateX(-50%)',
          }} />
        )}
      </div>
    );
  });
}
