import React from 'react';

const SEV_COLOR = {
  critical: '#f85149', high: '#f0883e', medium: '#d29922',
  low: '#58a6ff', info: '#8b949e',
};

export default function GraphEventDots({ nodeEventSeverity, edgeEventSeverity, nRef, eRef, tRef, gRRef, transformVersion }) {
  if ((!nodeEventSeverity || nodeEventSeverity.size === 0) &&
      (!edgeEventSeverity || edgeEventSeverity.size === 0)) {
    return null;
  }

  const t = tRef.current;
  const dots = [];

  if (nodeEventSeverity) {
    for (const [nid, sev] of nodeEventSeverity.entries()) {
      const node = nRef.current.find(n => n.id === nid);
      if (!node || node.x == null) continue;
      const r = (gRRef.current ? gRRef.current(node) : 10);
      const sx = (node.x + r * 0.7) * t.k + t.x;
      const sy = (node.y - r * 0.7) * t.k + t.y;
      dots.push({ key: `n:${nid}`, sx, sy, color: SEV_COLOR[sev] || '#8b949e' });
    }
  }

  if (edgeEventSeverity) {
    for (const [eid, sev] of edgeEventSeverity.entries()) {
      const edge = eRef.current.find(e => e.id === eid);
      if (!edge) continue;
      const src = typeof edge.source === 'object' ? edge.source : nRef.current.find(n => n.id === edge.source);
      const tgt = typeof edge.target === 'object' ? edge.target : nRef.current.find(n => n.id === edge.target);
      if (!src || !tgt || src.x == null || tgt.x == null) continue;
      const sx = ((src.x + tgt.x) / 2) * t.k + t.x;
      const sy = ((src.y + tgt.y) / 2) * t.k + t.y;
      dots.push({ key: `e:${eid}`, sx, sy, color: SEV_COLOR[sev] || '#8b949e' });
    }
  }

  return dots.map(d => (
    <div key={d.key} style={{
      position: 'absolute', left: d.sx, top: d.sy, zIndex: 49,
      width: 9, height: 9, borderRadius: '50%',
      background: d.color,
      border: '1.5px solid var(--bg)',
      boxShadow: `0 0 6px ${d.color}aa`,
      transform: 'translate(-50%, -50%)',
      pointerEvents: 'none',
    }} />
  ));
}
