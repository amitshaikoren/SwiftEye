import React, { useState } from 'react';

export default function SyntheticNodeForm({ onClose, onAddSyntheticNode }) {
  const [ip, setIp] = useState('');
  const [label, setLabel] = useState('');
  const [color, setColor] = useState('#f0883e');
  return (
    <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', zIndex: 200,
      background: 'var(--bgP)', border: '1px solid var(--bdL)', borderRadius: 10, padding: '16px 20px', minWidth: 260,
      boxShadow: '0 8px 32px rgba(0,0,0,.5)', fontFamily: 'var(--fn)',
    }}>
      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--tx)', marginBottom: 12 }}>Add Synthetic Node</div>
      {[['IP / ID', ip, setIp, 'e.g. 10.0.0.99'],['Label', label, setLabel, 'Optional display name']].map(([lbl, val, set, ph]) => (
        <div key={lbl} style={{ marginBottom: 10 }}>
          <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 3 }}>{lbl}</div>
          <input value={val} onChange={e => set(e.target.value)} placeholder={ph}
            style={{ width: '100%', boxSizing: 'border-box', padding: '5px 8px', fontSize: 11, background: 'var(--bgI)', border: '1px solid var(--bd)', borderRadius: 4, color: 'var(--tx)', fontFamily: 'var(--fn)', outline: 'none' }} />
        </div>
      ))}
      <div style={{ marginBottom: 14 }}>
        <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 3 }}>Color</div>
        <div style={{ display: 'flex', gap: 6 }}>
          {['#f0883e','#58a6ff','#3fb950','#bc8cff','#f78166','#e3b341'].map(c => (
            <div key={c} onClick={() => setColor(c)} style={{ width: 18, height: 18, borderRadius: '50%', background: c, cursor: 'pointer', border: color === c ? '2px solid white' : '2px solid transparent' }} />
          ))}
        </div>
      </div>
      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
        <button className="btn" onClick={onClose} style={{ fontSize: 10 }}>Cancel</button>
        <button className="btn" onClick={() => {
          if (!ip.trim()) return;
          onAddSyntheticNode?.({ ip: ip.trim(), label: label.trim() || ip.trim(), color });
          onClose();
        }} style={{ fontSize: 10, background: 'rgba(63,185,80,.1)', borderColor: '#3fb950', color: '#3fb950' }}>Add Node</button>
      </div>
      <div style={{ marginTop: 10, fontSize: 9, color: 'var(--txD)' }}>
        Synthetic nodes render with a dashed border and ✦ marker. They are saved to the backend and persist across page reloads.
      </div>
    </div>
  );
}
