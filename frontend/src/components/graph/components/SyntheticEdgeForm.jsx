import React, { useState } from 'react';

function NodePicker({ allNodes, onPick }) {
  return (
    <div style={{
      maxHeight: 140, overflowY: 'auto', border: '1px solid var(--bd)',
      borderRadius: 4, marginTop: 4, background: 'var(--bgC)',
    }}>
      {allNodes.length === 0 && (
        <div style={{ padding: '6px 8px', fontSize: 10, color: 'var(--txD)' }}>No nodes in current graph</div>
      )}
      {allNodes.map(n => (
        <div key={n.id} onClick={() => onPick(n.id)}
          style={{ padding: '4px 8px', fontSize: 10, cursor: 'pointer', borderBottom: '1px solid var(--bd)', display: 'flex', justifyContent: 'space-between', gap: 8 }}
          onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,.1)'}
          onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
        >
          <span style={{ color: 'var(--txM)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{n.label}</span>
          {n.label !== n.id && <span style={{ color: 'var(--txD)', fontSize: 9, flexShrink: 0 }}>{n.id.length > 20 ? n.id.slice(0,18) + '…' : n.id}</span>}
        </div>
      ))}
    </div>
  );
}

export default function SyntheticEdgeForm({ onClose, onAddSyntheticEdge, synEdgeSrc, nRef }) {
  const [src, setSrc] = useState(synEdgeSrc);
  const [tgt, setTgt] = useState('');
  const [protocol, setProtocol] = useState('');
  const [label, setLabel] = useState('');
  const [color, setColor] = useState('#f0883e');
  const [focusedField, setFocusedField] = useState(null); // 'src' | 'tgt'

  // Build a display-friendly node list: label (or id) + id
  const allNodes = nRef.current.map(n => ({
    id: n.id,
    label: n.metadata?.name || (n.hostnames?.length ? n.hostnames[0] : null) || n.id,
  }));

  return (
    <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', zIndex: 200,
      background: 'var(--bgP)', border: '1px solid var(--bdL)', borderRadius: 10, padding: '16px 20px', minWidth: 300, maxWidth: 360,
      boxShadow: '0 8px 32px rgba(0,0,0,.5)', fontFamily: 'var(--fn)',
    }}>
      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--tx)', marginBottom: 12 }}>Add Synthetic Edge</div>

      {/* Source */}
      <div style={{ marginBottom: 10 }}>
        <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 3 }}>Source node <span style={{ color: 'var(--acR)' }}>*</span></div>
        <input value={src} onChange={e => setSrc(e.target.value)}
          onFocus={() => setFocusedField('src')} onBlur={() => setTimeout(() => setFocusedField(f => f === 'src' ? null : f), 150)}
          placeholder="Click a node below or type ID"
          style={{ width: '100%', boxSizing: 'border-box', padding: '5px 8px', fontSize: 11, background: src ? 'rgba(88,166,255,.07)' : 'var(--bgI)', border: `1px solid ${src ? 'var(--ac)' : 'var(--bd)'}`, borderRadius: 4, color: 'var(--tx)', fontFamily: 'var(--fn)', outline: 'none' }} />
        {(focusedField === 'src' || !src) && <NodePicker allNodes={allNodes} onPick={id => { setSrc(id); setFocusedField(null); }} />}
      </div>

      {/* Target */}
      <div style={{ marginBottom: 10 }}>
        <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 3 }}>Target node <span style={{ color: 'var(--acR)' }}>*</span></div>
        <input value={tgt} onChange={e => setTgt(e.target.value)}
          onFocus={() => setFocusedField('tgt')} onBlur={() => setTimeout(() => setFocusedField(f => f === 'tgt' ? null : f), 150)}
          placeholder="Click a node below or type ID"
          style={{ width: '100%', boxSizing: 'border-box', padding: '5px 8px', fontSize: 11, background: tgt ? 'rgba(88,166,255,.07)' : 'var(--bgI)', border: `1px solid ${tgt ? 'var(--ac)' : 'var(--bd)'}`, borderRadius: 4, color: 'var(--tx)', fontFamily: 'var(--fn)', outline: 'none' }} />
        {(focusedField === 'tgt' || !tgt) && <NodePicker allNodes={allNodes} onPick={id => { setTgt(id); setFocusedField(null); }} />}
      </div>

      {/* Protocol + label */}
      {[['Protocol (optional)', protocol, setProtocol, 'e.g. HTTPS'],['Label (optional)', label, setLabel, 'Description']].map(([lbl, val, set, ph]) => (
        <div key={lbl} style={{ marginBottom: 10 }}>
          <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 3 }}>{lbl}</div>
          <input value={val} onChange={e => set(e.target.value)} placeholder={ph}
            style={{ width: '100%', boxSizing: 'border-box', padding: '5px 8px', fontSize: 11, background: 'var(--bgI)', border: '1px solid var(--bd)', borderRadius: 4, color: 'var(--tx)', fontFamily: 'var(--fn)', outline: 'none' }} />
        </div>
      ))}

      <div style={{ marginBottom: 14 }}>
        <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 3 }}>Color</div>
        <div style={{ display: 'flex', gap: 6 }}>
          {['#f0883e','#58a6ff','#3fb950','#bc8cff','#f78166','#e3b341'].map(col => (
            <div key={col} onClick={() => setColor(col)} style={{ width: 18, height: 18, borderRadius: '50%', background: col, cursor: 'pointer', border: color === col ? '2px solid white' : '2px solid transparent' }} />
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
        <button className="btn" onClick={onClose} style={{ fontSize: 10 }}>Cancel</button>
        <button className="btn" disabled={!src.trim() || !tgt.trim()} onClick={() => {
          onAddSyntheticEdge?.({ source: src.trim(), target: tgt.trim(), protocol: protocol.trim() || 'SYNTHETIC', label: label.trim(), color });
          onClose();
        }} style={{ fontSize: 10, background: 'rgba(63,185,80,.1)', borderColor: '#3fb950', color: '#3fb950', opacity: (!src.trim() || !tgt.trim()) ? 0.4 : 1 }}>Add Edge</button>
      </div>

      <div style={{ marginTop: 8, fontSize: 9, color: 'var(--txD)', lineHeight: 1.5 }}>
        Dashed line between the two nodes. Tip: right-click any node → "Draw synthetic edge from here" to pre-fill the source.
      </div>
    </div>
  );
}
