import React, { useState, useEffect, useRef } from 'react';
import { fetchLogs } from '../api';

export default function LogsPanel() {
  const [logs, setLogs] = useState([]);
  const [auto, setAuto] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    fetchLogs().then(d => setLogs(d.logs || [])).catch(e => console.error('Logs fetch error:', e));
    if (!auto) return;
    const iv = setInterval(() => {
      fetchLogs().then(d => setLogs(d.logs || [])).catch(() => {});
    }, 2000);
    return () => clearInterval(iv);
  }, [auto]);

  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [logs]);

  return (
    <div style={{ padding: 16, height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <div className="sh" style={{ marginBottom: 0 }}>Server Logs</div>
        <button className={'btn' + (auto ? ' on' : '')} onClick={() => setAuto(!auto)} style={{ fontSize: 9 }}>
          {auto ? 'Auto ●' : 'Paused'}
        </button>
      </div>
      <div ref={ref} style={{
        flex: 1, overflowY: 'auto', background: 'var(--bgC)',
        border: '1px solid var(--bd)', borderRadius: 'var(--rs)',
        padding: 8, fontSize: 10, lineHeight: 1.6, color: 'var(--txM)',
      }}>
        {logs.length === 0 && <div style={{ color: 'var(--txD)' }}>No logs yet. Logs appear after server activity.</div>}
        {logs.map((l, i) => (
          <div key={i} style={{
            padding: '1px 0', borderBottom: '1px solid var(--bd)',
            color: l.includes('ERROR') || l.includes('error') ? 'var(--acR)' : l.includes('WARNING') ? 'var(--acO)' : 'var(--txM)',
          }}>{l}</div>
        ))}
      </div>
    </div>
  );
}
