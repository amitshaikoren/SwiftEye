/**
 * WorkspaceSelector — Phase 3 landing screen.
 *
 * Shown by `WorkspaceProvider` when `/api/workspace/current` returns
 * `active=null` (no workspace picked yet or stored name no longer
 * registered). Lists every registered workspace as a card; clicking
 * one POSTs `/api/workspace/select` and reloads the page so the
 * provider re-initialises against the now-active workspace.
 *
 * Deliberate non-features (Phase 3 scope):
 *   - No in-app switching UI. Once picked, selection is sticky and
 *     only changes by editing/deleting `backend/settings.json`.
 *   - No per-workspace icons/illustrations. Text + tagline only until
 *     we know what forensic actually wants to say about itself.
 *
 * Descriptor source: `frontend/src/workspaces/<name>/index.js` exports
 * a `tagline` the card shows. Falls back to empty string.
 */

import React, { useState } from 'react';

export default function WorkspaceSelector({ available, onSwitch }) {
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);

  async function pick(name) {
    setBusy(name);
    setError(null);
    try {
      await onSwitch(name);
    } catch (e) {
      setError(e.message || String(e));
      setBusy(null);
    }
  }

  return (
    <div style={{
      width: '100%', height: '100vh', background: 'var(--bg)',
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      fontFamily: 'var(--fn)', color: 'var(--txM, #c9d1d9)',
    }}>
      <div style={{ fontSize: 22, marginBottom: 32, letterSpacing: 0.5 }}>SwiftEye</div>

      <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap', justifyContent: 'center' }}>
        {available.map(ws => {
          const isBusy = busy === ws.name;
          return (
            <button
              key={ws.name}
              onClick={() => pick(ws.name)}
              disabled={busy !== null}
              style={{
                width: 220, minHeight: 100, padding: '24px 22px',
                background: 'var(--bg)', border: '1px solid var(--bd)',
                borderRadius: 8, cursor: busy ? 'default' : 'pointer',
                textAlign: 'center', color: 'inherit', fontFamily: 'inherit',
                opacity: busy && !isBusy ? 0.5 : 1,
                transition: 'border-color 120ms',
                fontSize: 16,
              }}
              onMouseEnter={e => { if (!busy) e.currentTarget.style.borderColor = 'var(--ac)'; }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--bd)'; }}
            >
              <span style={{ color: 'var(--ac)' }}>{ws.label}</span>
              {isBusy && <span style={{ fontSize: 11, color: 'var(--txD, #8b949e)', marginLeft: 8 }}>…</span>}
            </button>
          );
        })}
      </div>

      {error && (
        <div style={{ marginTop: 24, fontSize: 12, color: 'var(--acR, #f85149)' }}>
          Failed to select workspace: {error}
        </div>
      )}
    </div>
  );
}
