/**
 * Forensic workspace — pre-capture screen (Phase 3 skeleton).
 *
 * Shown when the forensic workspace is active but no capture is loaded.
 * Phase 4 replaces this stub with an EVTX upload zone once the parser
 * lands. Kept copy-free of implementation details — users see a short
 * "not yet available" message, not a roadmap.
 */

import React from 'react';
import logoFullData from '@/logoFullData';

export default function ForensicUploadScreen() {
  return (
    <div style={{
      width: '100%', height: '100vh', background: 'var(--bg)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontFamily: 'var(--fn)',
    }}>
      <div style={{
        textAlign: 'center', padding: '64px 80px',
        border: '1.5px dashed rgba(88,166,255,.3)', borderRadius: 20,
        minWidth: 460, background: 'rgba(88,166,255,.02)',
      }}>
        <img src={logoFullData} alt="SwiftEye" style={{ height: 120, marginBottom: 40, opacity: 0.95 }} />
        <div style={{ fontSize: 16, color: 'var(--txM)', marginBottom: 10 }}>
          <span style={{ color: 'var(--ac)' }}>Forensic</span> ingestion is not available yet.
        </div>
        <div style={{ fontSize: 12, color: 'var(--txD)' }}>
          This workspace is a skeleton — EVTX / Sysmon support is in progress.
        </div>
      </div>
    </div>
  );
}
