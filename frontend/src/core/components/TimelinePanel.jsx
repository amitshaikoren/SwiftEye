/**
 * TimelinePanel — Full-width Session Gantt page.
 *
 * Replaces the right-panel Timeline. Gives Plotly the full viewport width
 * so large session counts are actually readable.
 *
 * Time scope slider is shared with the main graph — adjusting it here also
 * moves the main timeline range. The slider does NOT auto-run the chart;
 * click Run to compute against the current window.
 */
import React, { useState, useRef, useEffect } from 'react';
import { runResearchChart } from '../api';
import { fT, fTtime } from '../utils';
import { useFilterContext, toProtocolNames } from '../FilterContext';

// Inline gap-split sparkline for the time scope panel
function SegCanvas({ buckets, activeRange, globalStart, width, height }) {
  const ref = useRef(null);
  useEffect(() => {
    const c = ref.current;
    if (!c || !buckets.length || width < 1) return;
    const dpr = window.devicePixelRatio || 1;
    c.width = Math.round(width * dpr); c.height = Math.round(height * dpr);
    const ctx = c.getContext('2d'); ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, width, height);
    const max = Math.max(...buckets.map(b => b.packet_count || 0), 1);
    const bw = width / buckets.length;
    const [rS, rE] = activeRange;
    buckets.forEach((b, i) => {
      const v = b.packet_count || 0, gi = globalStart + i, x = i * bw;
      const h = (v / max) * (height - 2);
      ctx.fillStyle = (gi >= rS && gi <= rE) ? '#378ADD' : 'rgba(128,128,128,0.15)';
      ctx.fillRect(x, height - 1 - h, Math.max(bw - 0.4, 0.8), Math.max(h, v > 0 ? 2 : 0));
    });
  }, [buckets, activeRange, globalStart, width, height]);
  return <canvas ref={ref} style={{ width, height, display: 'block' }} />;
}

function GapSparkline({ parts, perSegW, GAP_W, timeRange, height }) {
  return (
    <div style={{ display: 'flex', alignItems: 'stretch', height }}>
      {parts.map((part, pi) => {
        if (part.type === 'gap') return (
          <div key={pi} style={{ width: GAP_W, flexShrink: 0, height, display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden', position: 'relative' }}>
            <svg width={GAP_W} height={height} style={{ position: 'absolute', top: 0, left: 0 }}>
              {[-8, 0, 8, 16, 24, 32, 40, 48].map((x, i) => (
                <line key={i} x1={x} y1={height} x2={x + height} y2={0} stroke="rgba(160,160,160,0.5)" strokeWidth="2" />
              ))}
            </svg>
            <span style={{ position: 'relative', fontSize: 9, color: 'var(--txD)', background: 'var(--bgP)', padding: '0 2px', zIndex: 1 }}>
              {part.gapSec < 3600 ? `${Math.round(part.gapSec/60)}m` : part.gapSec < 86400 ? `${(part.gapSec/3600).toFixed(1)}h` : `${(part.gapSec/86400).toFixed(1)}d`}
            </span>
          </div>
        );
        return <SegCanvas key={pi} buckets={part.buckets} activeRange={timeRange} globalStart={part.globalStart} width={Math.max(1, perSegW)} height={height} />;
      })}
    </div>
  );
}

function PlotlyChart({ figure, loading, error }) {
  const ref = useRef(null);

  useEffect(() => {
    if (!ref.current || !figure || !window.Plotly) return;
    window.Plotly.react(ref.current, figure.data, figure.layout, {
      responsive: true, displaylogo: false,
      modeBarButtonsToRemove: ['sendDataToCloud', 'lasso2d'],
    });
  }, [figure]);

  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(() => {
      if (ref.current && window.Plotly) window.Plotly.Plots.resize(ref.current);
    });
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);

  if (error) return (
    <div style={{ padding: 24, color: 'var(--acR)', fontSize: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
      {error}
    </div>
  );
  if (loading) return (
    <div style={{ height: 300, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10, color: 'var(--txM)', fontSize: 11 }}>
      <div style={{ width: 16, height: 16, border: '2px solid var(--bd)', borderTopColor: 'var(--ac)', borderRadius: '50%', animation: 'spin 0.7s linear infinite' }} />
      Building Gantt…
    </div>
  );
  if (!figure) return (
    <div style={{ height: 300, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--txD)', fontSize: 11 }}>
      Click <strong style={{ color: 'var(--txM)', margin: '0 4px' }}>Run</strong> to render the Gantt
    </div>
  );
  return <div ref={ref} style={{ width: '100%' }} />;
}

export default function TimelinePanel({
  sessions = [],
  timeline = [], timeRange = [0, 0], setTimeRange,
  bucketSec = 15, setBucketSec,
}) {
  const filterCtx = useFilterContext();
  const [figure, setFigure]   = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');

  const timeRangeRef = useRef(timeRange);
  const timelineRef  = useRef(timeline);
  useEffect(() => { timeRangeRef.current = timeRange; }, [timeRange]);
  useEffect(() => { timelineRef.current  = timeline;  }, [timeline]);

  const filterCtxRef = useRef(filterCtx);
  useEffect(() => { filterCtxRef.current = filterCtx; }, [filterCtx]);

  function handleRun() {
    if (!sessions.length) return;
    const tl = timelineRef.current;
    const tr = timeRangeRef.current;
    const f = filterCtxRef.current;
    const payload = {};
    if (tl.length) {
      const ts = tl[tr[0]]?.start_time;
      const te = tl[tr[1]]?.end_time;
      if (ts != null) payload._timeStart = ts;
      if (te != null) payload._timeEnd   = te;
    }
    // Pass active filter state so the Gantt respects current graph filters
    const protoNames = toProtocolNames(f.enabledP, f.allProtocolKeysCount);
    if (protoNames)      payload._filterProtocols  = protoNames;
    if (f.search?.trim()) payload._filterSearch    = f.search.trim();
    if (!f.includeIPv6)  payload._filterIncludeIpv6 = false;
    setLoading(true); setError('');
    runResearchChart('session_gantt', payload)
      .then(res => setFigure(res.figure))
      .catch(e  => {
        const msg = e.message || 'Gantt failed';
        setError(msg.toLowerCase().includes('no capture') || msg.includes('404')
          ? 'No capture loaded — upload a pcap file first.'
          : msg);
      })
      .finally(() => setLoading(false));
  }

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px', background: 'var(--bg)' }}>

      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--tx)', fontFamily: 'var(--fd)', marginBottom: 4 }}>
          Timeline
        </div>
        <div style={{ fontSize: 11, color: 'var(--txD)' }}>
          Session Gantt — one row per session, bars scaled to duration and coloured by protocol.
          {sessions.length > 0 && <span style={{ color: 'var(--txM)', marginLeft: 6 }}>{sessions.length} sessions in capture.</span>}
        </div>
      </div>

      {/* Time scope */}
      {timeline.length > 1 && (() => {
        const N = timeline.length;

        // Split timeline into segments and gaps (same logic as TimelineStrip)
        const parts = [];
        let i = 0;
        while (i < N) {
          if (timeline[i]?.is_gap) {
            parts.push({ type: 'gap', gapSec: timeline[i].gap_seconds || 0, globalStart: i, globalEnd: i });
            i++;
          } else {
            const segStart = i;
            while (i < N && !timeline[i]?.is_gap) i++;
            parts.push({ type: 'segment', buckets: timeline.slice(segStart, i), globalStart: segStart, globalEnd: i - 1 });
          }
        }
        const segments = parts.filter(p => p.type === 'segment');
        const hasGaps  = parts.some(p => p.type === 'gap');

        const fmtTs = t => t ? (() => {
          const d = new Date(t * 1000);
          return `${String(d.getDate()).padStart(2,'0')}/${String(d.getMonth()+1).padStart(2,'0')}/${d.getFullYear()} ${d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'})}`;
        })() : '—';
        const startTs = fmtTs(timeline[timeRange[0]]?.start_time);
        const endTs   = fmtTs(timeline[timeRange[1]]?.end_time);

        const GAP_W = 56;
        const sparkW = 560;
        const totalGapW = parts.filter(p => p.type === 'gap').length * GAP_W;
        const segW = Math.max(1, sparkW - totalGapW);
        const segCount = segments.length || 1;
        const perSegW = Math.floor(segW / segCount);

        return (
          <div style={{ background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 8, padding: '12px 16px', marginBottom: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--txD)" strokeWidth="2">
                  <circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>
                </svg>
                <span style={{ fontSize: 10, color: 'var(--txM)', textTransform: 'uppercase', letterSpacing: '.06em' }}>Time scope</span>
                {[1, 5, 15, 30, 60].map(s => (
                  <button key={s} className={'btn' + (bucketSec === s ? ' on' : '')}
                    onClick={() => setBucketSec(s)} style={{ padding: '1px 5px', fontSize: 9 }}>{s}s</button>
                ))}
                {hasGaps && (
                  <>
                    <span style={{ fontSize: 9, color: 'var(--txD)', margin: '0 2px' }}>·</span>
                    {segments.map((seg, si) => (
                      <button key={si}
                        className={'btn' + (timeRange[0] === seg.globalStart && timeRange[1] === seg.globalEnd ? ' on' : '')}
                        style={{ fontSize: 9, padding: '1px 7px' }}
                        onClick={() => setTimeRange([seg.globalStart, seg.globalEnd])}>
                        Burst {si + 1}
                      </button>
                    ))}
                    <button
                      className={'btn' + (timeRange[0] === 0 && timeRange[1] === N - 1 ? ' on' : '')}
                      style={{ fontSize: 9, padding: '1px 7px' }}
                      onClick={() => setTimeRange([0, N - 1])}>
                      All
                    </button>
                  </>
                )}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 9, fontFamily: 'var(--fn)', color: '#378ADD' }}>{startTs}</span>
                <span style={{ fontSize: 9, color: 'var(--txD)' }}>→</span>
                <span style={{ fontSize: 9, fontFamily: 'var(--fn)', color: '#1D9E75' }}>{endTs}</span>
              </div>
            </div>

            {/* Gap-split sparkline */}
            <GapSparkline parts={parts} perSegW={perSegW} GAP_W={GAP_W} timeRange={timeRange} height={22} />

            <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 6 }}>
              <span style={{ fontSize: 9, color: 'var(--txD)', minWidth: 30 }}>Start</span>
              <input type="range" min={0} max={N - 1} value={timeRange[0]}
                onChange={e => { const v = +e.target.value; setTimeRange([v, Math.max(v, timeRange[1])]); }}
                style={{ flex: 1 }} />
              <span style={{ fontSize: 9, color: '#378ADD', minWidth: 155, textAlign: 'right', fontFamily: 'var(--fn)' }}>{startTs}</span>
            </div>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 3 }}>
              <span style={{ fontSize: 9, color: 'var(--txD)', minWidth: 30 }}>End</span>
              <input type="range" min={0} max={N - 1} value={timeRange[1]}
                onChange={e => { const v = +e.target.value; setTimeRange([Math.min(timeRange[0], v), v]); }}
                style={{ flex: 1 }} />
              <span style={{ fontSize: 9, color: '#1D9E75', minWidth: 155, textAlign: 'right', fontFamily: 'var(--fn)' }}>{endTs}</span>
            </div>

            <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ fontSize: 9, color: 'var(--txD)' }}>
                Adjust the window then click <strong style={{ color: 'var(--txM)' }}>Run</strong> — the slider does not auto-recompute.
                {(filterCtx.enabledP.size < filterCtx.allProtocolKeysCount || filterCtx.search || !filterCtx.includeIPv6) && (
                  <span style={{ color: 'var(--ac)', marginLeft: 6 }}>· active filters will be applied</span>
                )}
              </div>
              <button
                className="btn"
                onClick={handleRun}
                disabled={loading || !sessions.length}
                style={{
                  padding: '5px 20px', fontSize: 11,
                  background: loading ? 'transparent' : 'rgba(88,166,255,.1)',
                  borderColor: 'var(--ac)', color: 'var(--ac)',
                  opacity: loading ? 0.5 : 1,
                }}
              >
                {loading ? 'Running…' : 'Run'}
              </button>
            </div>
          </div>
        );
      })()}

      {/* Run button when no time scope available */}
      {timeline.length <= 1 && sessions.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <button className="btn" onClick={handleRun} disabled={loading}
            style={{ padding: '5px 20px', fontSize: 11, background: 'rgba(88,166,255,.1)', borderColor: 'var(--ac)', color: 'var(--ac)' }}>
            {loading ? 'Running…' : 'Run'}
          </button>
        </div>
      )}

      {sessions.length === 0 && (
        <div style={{ color: 'var(--txD)', fontSize: 11, marginTop: 40, textAlign: 'center' }}>
          {timeline.length === 0
            ? 'No capture loaded — upload a pcap file to use the Timeline.'
            : 'No sessions in this capture.'}
        </div>
      )}

      {/* Chart */}
      <div style={{ background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 10, overflow: 'hidden' }}>
        <div style={{ padding: '8px 8px 4px', background: 'var(--bg)' }}>
          <PlotlyChart figure={figure} loading={loading} error={error} />
        </div>
      </div>

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
