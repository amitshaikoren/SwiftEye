/**
 * TypePickerDialog — shown when automatic format detection fails.
 * Lets the user manually select the file type before retrying the upload.
 */
import { useState } from 'react';

export default function TypePickerDialog({ fileName, availableAdapters = [], onConfirm, onCancel }) {
  const [selected, setSelected] = useState(availableAdapters[0] || '');

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 9999,
      background: 'rgba(0,0,0,0.6)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        background: 'var(--bg2)', border: '1px solid var(--bd)',
        borderRadius: 8, padding: '24px 28px', width: 420, maxWidth: '90vw',
        boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
      }}>
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 6 }}>Unknown file format</div>
        <div style={{ fontSize: 12, color: 'var(--txD)', marginBottom: 16 }}>
          Could not automatically detect the type of <strong style={{ color: 'var(--tx)' }}>{fileName}</strong>.
          Select the format manually to continue.
        </div>

        <label style={{ fontSize: 11, color: 'var(--txD)', display: 'block', marginBottom: 6 }}>
          File format
        </label>
        <select
          value={selected}
          onChange={e => setSelected(e.target.value)}
          style={{
            width: '100%', padding: '7px 10px', fontSize: 12,
            background: 'var(--bg)', border: '1px solid var(--bd)',
            borderRadius: 4, color: 'var(--tx)', marginBottom: 20,
          }}
        >
          {availableAdapters.map(name => (
            <option key={name} value={name}>{name}</option>
          ))}
        </select>

        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button className="btn" onClick={onCancel}
            style={{ fontSize: 12, padding: '6px 16px' }}>
            Cancel
          </button>
          <button className="btn btn-primary" onClick={() => onConfirm(selected)}
            disabled={!selected}
            style={{ fontSize: 12, padding: '6px 16px' }}>
            Load as {selected || '…'}
          </button>
        </div>
      </div>
    </div>
  );
}
