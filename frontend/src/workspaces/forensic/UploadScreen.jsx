/**
 * Forensic workspace — EVTX upload screen (Phase 5).
 *
 * Uses the handleDrop / handleFileInput props injected by useCaptureLoad,
 * which now dispatches to workspace.uploadFile (forensicEvtx) when the
 * forensic workspace descriptor provides it.
 *
 * Props mirror the network UploadScreen so App.jsx can call both uniformly.
 */

import React, { useState } from 'react';
import logoFullData from '@/logoFullData';
import { selectWorkspace } from '@core/api';
import { useWorkspace } from '@/WorkspaceProvider';

export default function ForensicUploadScreen({
  loading, loadMsg,
  handleDrop, handleFileInput,
  error,
}) {
  const workspace = useWorkspace();
  const [switching, setSwitching] = useState(false);

  const otherWorkspaces = (workspace.available || []).filter(w => w.name !== workspace.name);

  async function switchTo(name) {
    setSwitching(true);
    try {
      await selectWorkspace(name);
      window.location.reload();
    } catch {
      setSwitching(false);
    }
  }

  return (
    <div style={{
      width: '100%', height: '100vh', background: 'var(--bg)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      position: 'relative',
    }}>
      {loading ? (
        <div style={{ textAlign: 'center' }}>
          <div style={{
            width: 40, height: 40, border: '3px solid var(--bd)',
            borderTopColor: '#4fc3f7', borderRadius: '50%',
            animation: 'spin 0.8s linear infinite', margin: '0 auto 16px',
          }} />
          <div style={{ color: 'var(--txM)', fontSize: 13, fontFamily: 'var(--fn)' }}>
            {loadMsg || 'Parsing events…'}
          </div>
        </div>
      ) : (
        <div
          onDrop={handleDrop}
          onDragOver={e => e.preventDefault()}
          onClick={() => document.getElementById('evtx-up').click()}
          style={{
            textAlign: 'center', padding: '64px 80px',
            border: '1.5px dashed rgba(79,195,247,.35)', borderRadius: 20,
            cursor: 'pointer', minWidth: 460,
            background: 'rgba(79,195,247,.02)',
          }}
        >
          <img src={logoFullData} alt="SwiftEye" style={{ height: 120, marginBottom: 40, opacity: 0.95 }} />
          <div style={{ fontSize: 16, color: 'var(--txM)', marginBottom: 8, fontFamily: 'var(--fn)' }}>
            Drop an <span style={{ color: '#4fc3f7' }}>EVTX</span> file, or click to browse
          </div>
          <div style={{ fontSize: 11, color: 'var(--txD)', fontFamily: 'var(--fn)' }}>
            Sysmon event logs (.evtx) · EIDs 1, 3, 11, 13
          </div>
          {error && (
            <div style={{ marginTop: 18, fontSize: 11, color: 'var(--acR)', fontFamily: 'var(--fn)' }}>
              {error}
            </div>
          )}
          <input
            id="evtx-up"
            type="file"
            accept=".evtx"
            style={{ display: 'none' }}
            onChange={handleFileInput}
          />
        </div>
      )}

      {/* Workspace switcher link */}
      {otherWorkspaces.length > 0 && !loading && (
        <div style={{ position: 'absolute', bottom: 24, right: 28, display: 'flex', gap: 12 }}>
          {otherWorkspaces.map(w => (
            <button
              key={w.name}
              onClick={() => switchTo(w.name)}
              disabled={switching}
              style={{
                background: 'none', border: 'none', cursor: switching ? 'default' : 'pointer',
                color: 'var(--txD)', fontSize: 11, fontFamily: 'var(--fn)',
                textDecoration: 'underline', padding: 0, opacity: switching ? 0.5 : 1,
              }}
            >
              {switching ? 'Switching…' : `Switch to ${w.label || w.name}`}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
