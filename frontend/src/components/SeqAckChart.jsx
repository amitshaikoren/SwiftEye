/**
 * SeqAckChart.jsx — inline Seq/Ack Timeline chart for SessionDetail.
 *
 * Calls the research endpoint directly via runResearchChart.
 * Props: sessionId, session
 */

import React, { useState, useEffect, useRef } from 'react';
import { runResearchChart } from '../api';

export default function SeqAckChart({ sessionId, session }) {
  const [figure, setFigure] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [mode, setMode] = useState('time');  // 'time' | 'seqack'
  const plotRef = useRef(null);

  useEffect(() => {
    if (!figure || !plotRef.current || !window.Plotly) return;
    window.Plotly.react(plotRef.current, figure.data, figure.layout, {
      responsive: true, displayModeBar: false,
    });
  }, [figure]);

  async function handleRun() {
    setLoading(true); setError(''); setFigure(null);
    try {
      const res = await runResearchChart('seq_ack_timeline', { session_id: sessionId, mode });
      setFigure(res.figure);
    } catch (e) {
      setError(e.message || 'Chart failed');
    } finally {
      setLoading(false);
    }
  }

  const isnInit = session?.seq_isn_init;
  const isnResp = session?.seq_isn_resp;

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
        <div style={{ fontSize: 10, color: 'var(--txD)', flex: 1 }}>
          {mode === 'time'
            ? 'Bytes sent over time. Slope = throughput, flat = stall, step back = retransmit.'
            : 'SEQ vs ACK (both normalized). Diagonal = healthy flow, flat = one side stopped.'}
        </div>
        <div style={{ display: 'flex', gap: 2 }}>
          <button className={'btn' + (mode === 'time' ? ' on' : '')}
            onClick={() => { setMode('time'); setFigure(null); }}
            style={{ fontSize: 9 }}>Bytes/time</button>
          <button className={'btn' + (mode === 'seqack' ? ' on' : '')}
            onClick={() => { setMode('seqack'); setFigure(null); }}
            style={{ fontSize: 9 }}>SEQ/ACK</button>
        </div>
        <button className="btn" onClick={handleRun} disabled={loading}
          style={{ fontSize: 10, padding: '3px 12px', background: loading ? undefined : 'rgba(88,166,255,.1)', borderColor: 'var(--ac)', color: 'var(--ac)' }}>
          {loading ? '…' : 'Run'}
        </button>
      </div>
      {error && (
        <div style={{ fontSize: 10, color: 'var(--acR)', padding: '8px 0' }}>{error}</div>
      )}
      {!figure && !loading && !error && (
        <div style={{ fontSize: 10, color: 'var(--txD)', textAlign: 'center', padding: '32px 0' }}>
          Click Run to compute the chart
        </div>
      )}
      {loading && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 260, color: 'var(--txD)', fontSize: 11 }}>
          Computing…
        </div>
      )}
      {figure && !loading && (
        <div ref={plotRef} style={{ width: '100%', height: 260 }} />
      )}
      {(isnInit > 0 || isnResp > 0) && (
        <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 2 }}>
          <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 2 }}>Initial sequence numbers (ISN)</div>
          {isnInit > 0 && (
            <div style={{ fontSize: 9, fontFamily: 'var(--fn)', display: 'flex', gap: 6, alignItems: 'center' }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#3fb950', flexShrink: 0, display: 'inline-block' }} />
              <span style={{ color: 'var(--txD)' }}>Init</span>
              <span style={{ color: 'var(--txM)' }}>{isnInit.toLocaleString()}</span>
            </div>
          )}
          {isnResp > 0 && (
            <div style={{ fontSize: 9, fontFamily: 'var(--fn)', display: 'flex', gap: 6, alignItems: 'center' }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#58a6ff', flexShrink: 0, display: 'inline-block' }} />
              <span style={{ color: 'var(--txD)' }}>Resp</span>
              <span style={{ color: 'var(--txM)' }}>{isnResp.toLocaleString()}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
