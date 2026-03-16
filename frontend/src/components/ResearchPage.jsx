import React, { useState, useEffect, useRef } from 'react';
import { fetchResearchCharts, runResearchChart } from '../api';
import { fT, fTtime } from '../utils';
import Sparkline from './Sparkline';

// ── Error boundary — prevents a chart crash from blanking the whole panel ───────
class ChartErrorBoundary extends React.Component {
  constructor(props) { super(props); this.state = { error: null }; }
  static getDerivedStateFromError(e) { return { error: e?.message || String(e) }; }
  render() {
    if (this.state.error) return (
      <div style={{ padding: '12px 16px', background: 'rgba(248,81,73,.08)', border: '1px solid rgba(248,81,73,.2)',
        borderRadius: 8, color: 'var(--acR)', fontSize: 11, marginBottom: 16 }}>
        Chart render error: {this.state.error}
      </div>
    );
    return this.props.children;
  }
}

// ── PlotlyChart ───────────────────────────────────────────────────────────────
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
    <div style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10, color: 'var(--txM)', fontSize: 11 }}>
      <div style={{ width: 16, height: 16, border: '2px solid var(--bd)', borderTopColor: 'var(--ac)', borderRadius: '50%', animation: 'spin 0.7s linear infinite' }} />
      Computing…
    </div>
  );
  if (!figure) return (
    <div style={{ height: 200, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--txD)', fontSize: 11 }}>
      Fill in the parameters above and click Run
    </div>
  );
  return <div ref={ref} style={{ width: '100%', minHeight: 300 }} />;
}

// ── IpParamInput ─────────────────────────────────────────────────────────────────
// Input for chart params. If type=ip and availableIps are provided, shows a
// filterable dropdown of IPs from the current graph.
function IpParamInput({ param: p, value, availableIps, onChange, onEnter }) {
  const [showDrop, setShowDrop] = React.useState(false);
  const [filter, setFilter] = React.useState('');
  const wrapRef = React.useRef(null);

  // Close dropdown on outside click
  React.useEffect(() => {
    function h(e) { if (wrapRef.current && !wrapRef.current.contains(e.target)) setShowDrop(false); }
    if (showDrop) document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [showDrop]);

  const filtered = availableIps.length
    ? availableIps.filter(ip => !value || ip.toLowerCase().includes(value.toLowerCase())).slice(0, 12)
    : [];

  return (
    <div ref={wrapRef} style={{ display: 'flex', flexDirection: 'column', gap: 3, position: 'relative' }}>
      <label style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em' }}>
        {p.label}{p.required && <span style={{ color: 'var(--acR)', marginLeft: 2 }}>*</span>}
      </label>
      <input className="inp"
        style={{ width: 150, fontFamily: 'var(--fn)', fontSize: 11 }}
        placeholder={p.placeholder || p.label}
        value={value}
        onChange={e => { onChange(e.target.value); setFilter(e.target.value); }}
        onFocus={() => setShowDrop(true)}
        onKeyDown={e => {
          if (e.key === 'Enter') { setShowDrop(false); onEnter(); }
          if (e.key === 'Escape') setShowDrop(false);
        }}
      />
      {showDrop && filtered.length > 0 && (
        <div style={{
          position: 'absolute', top: '100%', left: 0, zIndex: 200,
          background: 'var(--bgP)', border: '1px solid var(--bd)',
          borderRadius: 'var(--rs)', marginTop: 2, minWidth: 150, maxHeight: 160,
          overflowY: 'auto', boxShadow: '0 4px 16px rgba(0,0,0,.4)',
        }}>
          {filtered.map(ip => (
            <div key={ip}
              onMouseDown={() => { onChange(ip); setShowDrop(false); }}
              style={{ padding: '5px 10px', fontSize: 11, cursor: 'pointer', fontFamily: 'var(--fn)', color: 'var(--txM)' }}
              onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,.12)'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
            >{ip}</div>
          ))}
        </div>
      )}
    </div>
  );
}


// ── ChartCard ─────────────────────────────────────────────────────────────────
// getTimeBounds is called at Run time only — slider changes don't trigger rerenders
function ChartCard({ chart, investigatedIp = '', availableIps = [], getTimeBounds, prefillValues = {} }) {
  const ipParams = (chart.params || []).filter(p => p.type === 'ip');
  const firstIpParam = ipParams[0] || null;

  const [values, setValues] = useState(() => {
    const init = {};
    (chart.params || []).forEach(p => {
      if (prefillValues[p.name] !== undefined) {
        init[p.name] = prefillValues[p.name];
      } else if (p.type === 'ip' && investigatedIp && ipParams.indexOf(p) === 0) {
        init[p.name] = investigatedIp;
      } else {
        init[p.name] = p.default || '';
      }
    });
    return init;
  });

  // Update values when prefillValues changes (e.g. different session opened from SessionDetail)
  useEffect(() => {
    if (!prefillValues || Object.keys(prefillValues).length === 0) return;
    setValues(prev => ({ ...prev, ...prefillValues }));
  }, [JSON.stringify(prefillValues)]);

  // Track the last IP we auto-filled so we can tell if the user edited it.
  // If the current value still equals the last auto-fill, update it when
  // investigatedIp changes. If the user changed it manually, leave it alone.
  const lastAutoFill = React.useRef(investigatedIp);

  useEffect(() => {
    if (!firstIpParam || !investigatedIp) return;
    setValues(prev => {
      // Only update if the field still holds the previous auto-filled value
      // (i.e. the user hasn't manually typed something different)
      if (prev[firstIpParam.name] === lastAutoFill.current ||
          prev[firstIpParam.name] === '') {
        lastAutoFill.current = investigatedIp;
        return { ...prev, [firstIpParam.name]: investigatedIp };
      }
      return prev;
    });
  }, [investigatedIp]);
  const [figure, setFigure]   = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');

  async function handleRun() {
    for (const p of chart.params || []) {
      if (p.required && !values[p.name]?.trim()) {
        setError(`"${p.label}" is required`); return;
      }
    }
    setLoading(true); setError('');
    try {
      const { timeStart, timeEnd } = getTimeBounds();
      const payload = { ...values };
      if (timeStart != null) payload._timeStart = timeStart;
      if (timeEnd   != null) payload._timeEnd   = timeEnd;
      const res = await runResearchChart(chart.name, payload);
      setFigure(res.figure);
    } catch (e) {
      const msg = e.message || 'Chart computation failed';
      // Give a clearer message for the common case of running before uploading a pcap
      setError(msg.toLowerCase().includes('no capture') || msg.includes('404')
        ? 'No capture loaded — upload a pcap file first, then run charts.'
        : msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 10, overflow: 'hidden', marginBottom: 16 }}>
      <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--bd)', display: 'flex', alignItems: 'flex-start', gap: 12 }}>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--tx)', marginBottom: 3 }}>{chart.title}</div>
          <div style={{ fontSize: 10, color: 'var(--txD)', fontStyle: 'italic' }}>{chart.description}</div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          {(chart.params || []).map(p => (
            <IpParamInput
              key={p.name}
              param={p}
              value={values[p.name]}
              availableIps={p.type === 'ip' ? availableIps : []}
              onChange={v => setValues(prev => ({ ...prev, [p.name]: v }))}
              onEnter={handleRun}
            />
          ))}
          <button className="btn" onClick={handleRun} disabled={loading}
            style={{ marginTop: 14, padding: '5px 16px', fontSize: 11,
              background: loading ? 'transparent' : 'rgba(88,166,255,.1)',
              borderColor: 'var(--ac)', color: 'var(--ac)', opacity: loading ? 0.5 : 1 }}>
            {loading ? 'Running…' : 'Run'}
          </button>
        </div>
      </div>
      <div style={{ padding: '8px 8px 4px', background: 'var(--bg)' }}>
        <PlotlyChart figure={figure} loading={loading} error={error} />
      </div>
    </div>
  );
}

// ── ResearchPage ──────────────────────────────────────────────────────────────
// Simple IPv4 check — used to decide if the search term is a bare IP address
// that can be used to pre-fill Research chart params.
function looksLikeIPv4(s) {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s.trim());
}

export default function ResearchPage({
  investigatedIp = '',
  searchIp = '',          // search term from the toolbar, if it looks like an IP
  seqAckSessionId = '',  // pre-fills seq_ack_timeline chart when opened from SessionDetail
  availableIps = [],      // IPs from current graph nodes, for autocomplete
  timeline = [], timeRange = [0, 0], setTimeRange,
  bucketSec = 15, setBucketSec,
}) {
  // investigatedIp (from Investigate context menu) takes priority over searchIp
  const effectiveIp = investigatedIp || searchIp;
  const [charts, setCharts]   = useState([]);
  const [loadErr, setLoadErr] = useState('');

  // Refs so getTimeBounds() always reads latest values without stale closures
  const timeRangeRef = useRef(timeRange);
  const timelineRef  = useRef(timeline);
  useEffect(() => { timeRangeRef.current = timeRange; }, [timeRange]);
  useEffect(() => { timelineRef.current  = timeline;  }, [timeline]);

  useEffect(() => {
    fetchResearchCharts()
      .then(d => {
        // session_gantt lives in the Timeline panel — exclude it here
        const filtered = (d.charts || []).filter(c => c.name !== 'session_gantt');
        setCharts(filtered);
      })
      .catch(e => {
        // Real error (server down, unexpected 500, etc.) — show it.
        // A 404 from _require_capture no longer happens because the list
        // endpoint was fixed to not require a capture.
        setLoadErr(e.message);
      });
  }, []);

  function getTimeBounds() {
    const tl = timelineRef.current;
    const tr = timeRangeRef.current;
    if (!tl.length) return { timeStart: null, timeEnd: null };
    return {
      timeStart: tl[tr[0]]?.start_time ?? null,
      timeEnd:   tl[tr[1]]?.end_time   ?? null,
    };
  }

  const timeLabel = (() => {
    if (!timeline.length) return 'Full capture';
    const s = timeline[timeRange[0]], e = timeline[timeRange[1]];
    return s && e ? `${fTtime(s.start_time)} — ${fTtime(e.end_time)}` : 'Full capture';
  })();
  const isFullRange = !timeline.length || (timeRange[0] === 0 && timeRange[1] === timeline.length - 1);

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px', background: 'var(--bg)' }}>
      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--tx)', fontFamily: 'var(--fd)', marginBottom: 4 }}>Research</div>
        <div style={{ fontSize: 11, color: 'var(--txD)' }}>
          On-demand charts for data exploration. Each chart runs server-side against the loaded capture — the browser only renders the result.
        </div>
      </div>

      {/* Time scope block */}
      {timeline.length > 1 && (
        <div style={{ background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 8, padding: '12px 16px', marginBottom: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--txD)" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>
              </svg>
              <span style={{ fontSize: 10, color: 'var(--txM)', textTransform: 'uppercase', letterSpacing: '.06em' }}>Time scope</span>
              {[5, 15, 30, 60].map(s => (
                <button key={s} className={'btn' + (bucketSec === s ? ' on' : '')}
                  onClick={() => setBucketSec(s)} style={{ padding: '1px 5px', fontSize: 8 }}>{s}s</button>
              ))}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 10, color: isFullRange ? 'var(--txD)' : 'var(--ac)', fontFamily: 'var(--fn)' }}>{timeLabel}</span>
              {!isFullRange && (
                <button className="btn" style={{ fontSize: 9, padding: '2px 7px' }}
                  onClick={() => setTimeRange([0, timeline.length - 1])}>Reset</button>
              )}
            </div>
          </div>

          <Sparkline data={timeline} width={600} height={22} activeRange={timeRange} />

          <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 6 }}>
            <span style={{ fontSize: 9, color: 'var(--txD)', minWidth: 30 }}>Start</span>
            <input type="range" min={0} max={timeline.length - 1} value={timeRange[0]}
              onChange={e => { const v = +e.target.value; setTimeRange([v, Math.max(v, timeRange[1])]); }}
              style={{ flex: 1 }} />
            <span style={{ fontSize: 9, color: 'var(--txD)', minWidth: 20, textAlign: 'center' }}>{timeRange[0]}</span>
          </div>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 3 }}>
            <span style={{ fontSize: 9, color: 'var(--txD)', minWidth: 30 }}>End</span>
            <input type="range" min={0} max={timeline.length - 1} value={timeRange[1]}
              onChange={e => { const v = +e.target.value; setTimeRange([Math.min(timeRange[0], v), v]); }}
              style={{ flex: 1 }} />
            <span style={{ fontSize: 9, color: 'var(--txD)', minWidth: 20, textAlign: 'center' }}>{timeRange[1]}</span>
          </div>

          <div style={{ marginTop: 8, fontSize: 9, color: 'var(--txD)' }}>
            Adjust the window above then click <strong style={{ color: 'var(--txM)' }}>Run</strong> on any chart — the slider does not auto-recompute.
          </div>
        </div>
      )}

      {loadErr && (
        <div style={{ padding: '12px 16px', background: 'rgba(248,81,73,.08)', border: '1px solid rgba(248,81,73,.2)', borderRadius: 8, color: 'var(--acR)', fontSize: 11, marginBottom: 16 }}>
          Failed to load research charts: {loadErr}
        </div>
      )}
      {charts.length === 0 && !loadErr && (
        <div style={{ color: 'var(--txD)', fontSize: 11, marginTop: 40, textAlign: 'center' }}>
          No research charts registered on the server.
          <div style={{ fontSize: 10, color: 'var(--txD)', marginTop: 6, opacity: 0.6 }}>
            Check that the server started correctly and research chart files are present.
          </div>
        </div>
      )}

      {charts.map(chart => (
        <ChartErrorBoundary key={chart.name}>
          <ChartCard chart={chart} investigatedIp={effectiveIp}
            prefillValues={chart.name === 'seq_ack_timeline' && seqAckSessionId ? { session_id: seqAckSessionId } : {}}
            availableIps={availableIps} getTimeBounds={getTimeBounds} />
        </ChartErrorBoundary>
      ))}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
