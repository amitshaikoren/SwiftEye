import React, { useState, useEffect, useRef } from 'react';
import { api, runCustomChart } from '../../../core/api';
import { fTtime } from '../../../core/utils';
import Sparkline from '../../../core/components/Sparkline';
import ScopePill from '../../../core/components/ScopePill';
import { useFilterContext, toProtocolNames } from '../../../core/FilterContext';
import { STORAGE_KEYS } from '../../../core/storageKeys';
import { useWorkspace } from '../../../WorkspaceProvider';

export const DEFAULT_CARD_HEIGHT = 380;

// ── Error boundary ────────────────────────────────────────────────────────────
class ChartErrorBoundary extends React.Component {
  constructor(props) { super(props); this.state = { error: null }; }
  static getDerivedStateFromError(e) { return { error: e?.message || String(e) }; }
  render() {
    if (this.state.error) return (
      <div style={{ padding: '12px 16px', background: 'rgba(248,81,73,.08)', border: '1px solid rgba(248,81,73,.2)',
        borderRadius: 8, color: 'var(--acR)', fontSize: 11 }}>
        Chart render error: {this.state.error}
      </div>
    );
    return this.props.children;
  }
}

// ── PlotlyChart ───────────────────────────────────────────────────────────────
function PlotlyChart({ figure, loading, error, isWide, fillHeight }) {
  const ref = useRef(null);

  useEffect(() => {
    if (!ref.current || !figure || !window.Plotly) return;
    window.Plotly.react(ref.current, figure.data, figure.layout, {
      responsive: true, displaylogo: false,
      modeBarButtonsToRemove: ['sendDataToCloud', 'lasso2d'],
    });
  }, [figure]);

  // Resize when slot width changes (wide toggle)
  useEffect(() => {
    if (!ref.current || !window.Plotly) return;
    window.Plotly.Plots.resize(ref.current);
  }, [isWide]);

  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(() => {
      if (ref.current && window.Plotly) window.Plotly.Plots.resize(ref.current);
    });
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);

  if (error) return (
    <div style={{ padding: 16, color: 'var(--acR)', fontSize: 11, display: 'flex', alignItems: 'center', gap: 8 }}>
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
      {error}
    </div>
  );
  if (loading) return (
    <div style={{ height: 160, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10, color: 'var(--txM)', fontSize: 11 }}>
      <div style={{ width: 14, height: 14, border: '2px solid var(--bd)', borderTopColor: 'var(--ac)', borderRadius: '50%', animation: 'spin 0.7s linear infinite' }} />
      Computing…
    </div>
  );
  if (!figure) return (
    <div style={{ height: 120, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--txD)', fontSize: 11 }}>
      Fill in params above and click Run
    </div>
  );
  return <div ref={ref} style={{ width: '100%', ...(fillHeight ? { height: '100%' } : { minHeight: 220 }) }} />;
}

// ── IpParamInput ──────────────────────────────────────────────────────────────
function IpParamInput({ param: p, value, availableIps, onChange, onEnter }) {
  const [showDrop, setShowDrop] = useState(false);
  const wrapRef = useRef(null);

  useEffect(() => {
    function h(e) { if (wrapRef.current && !wrapRef.current.contains(e.target)) setShowDrop(false); }
    if (showDrop) document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [showDrop]);

  const filtered = availableIps.length
    ? availableIps.filter(ip => !value || ip.toLowerCase().includes(value.toLowerCase())).slice(0, 12)
    : [];

  return (
    <div ref={wrapRef} style={{ display: 'flex', flexDirection: 'column', gap: 2, position: 'relative' }}>
      <label style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em' }}>
        {p.label}{p.required && <span style={{ color: 'var(--acR)', marginLeft: 2 }}>*</span>}
      </label>
      <input className="inp"
        style={{ width: 140, fontFamily: 'var(--fn)', fontSize: 11 }}
        placeholder={p.placeholder || p.label}
        value={value}
        onChange={e => { onChange(e.target.value); }}
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
          borderRadius: 'var(--rs)', marginTop: 2, minWidth: 140, maxHeight: 160,
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

// ── useScopeState ─────────────────────────────────────────────────────────────
function useScopeState(key) {
  const [scope, setScope] = useState(() => {
    try { return localStorage.getItem(key) || 'scoped'; } catch { return 'scoped'; }
  });
  const onChange = (v) => {
    setScope(v);
    try { localStorage.setItem(key, v); } catch {}
  };
  return [scope, onChange];
}

// ── PlacedCard — a chart placed in a slot ─────────────────────────────────────
export default function PlacedCard({
  chart, investigatedIp, availableIps,
  globalTimeBounds,
  timeline, timeRange: globalRange, bucketSec, setBucketSec,
  isWide, onToggleWide,
  cardHeight, onResize,
  onRemove, onExpand, onEdit,
  slotId,
}) {
  const filterCtx = useFilterContext();
  const workspace = useWorkspace();
  const researchApiBase = workspace.research?.apiBase || '/api/research';
  const [scope, setScope] = useScopeState(STORAGE_KEYS.scopeSlot(slotId));
  function handleResizeStart(e) {
    e.preventDefault();
    const startY = e.clientY;
    const startHeight = cardHeight || DEFAULT_CARD_HEIGHT;
    function onMove(e) {
      const newHeight = Math.max(120, startHeight + (e.clientY - startY));
      onResize(newHeight);
    }
    function onUp() {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    }
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  }
  // ── per-card filter state (used only when scope === 'all' / custom override)
  const [useCustomTime, setUseCustomTime] = useState(false);
  const [cardTimeRange, setCardTimeRange] = useState([0, Math.max(0, (timeline?.length ?? 1) - 1)]);
  const [protocols, setProtocols]     = useState(() => new Set(filterCtx.protocolList));
  const [search, setSearch]           = useState('');
  const [includeIpv6, setIncludeIpv6] = useState(true);
  const [filtersOpen, setFiltersOpen] = useState(false);

  // Update card time range ceiling when timeline grows
  useEffect(() => {
    if (!useCustomTime && timeline?.length) {
      setCardTimeRange([0, timeline.length - 1]);
    }
  }, [timeline?.length, useCustomTime]);

  // ── param state
  const ipParams = (chart.params || []).filter(p => p.type === 'ip');
  const firstIpParam = ipParams[0] || null;
  const lastAutoFill = useRef(investigatedIp);

  const [values, setValues] = useState(() => {
    const init = {};
    (chart.params || []).forEach(p => {
      if (p.type === 'ip' && investigatedIp && ipParams.indexOf(p) === 0) {
        init[p.name] = investigatedIp;
      } else {
        init[p.name] = p.default || '';
      }
    });
    return init;
  });

  useEffect(() => {
    if (!firstIpParam || !investigatedIp) return;
    setValues(prev => {
      if (prev[firstIpParam.name] === lastAutoFill.current || prev[firstIpParam.name] === '') {
        lastAutoFill.current = investigatedIp;
        return { ...prev, [firstIpParam.name]: investigatedIp };
      }
      return prev;
    });
  }, [investigatedIp]);

  const [figure, setFigure]         = useState(null);
  const [loading, setLoading]       = useState(false);
  const [error, setError]           = useState('');
  // Per-chart filter schema — initialized from chart.entry_schema (static, available
  // immediately). Updated after first run with any dynamic list options from the backend.
  // Shape: { fieldName: { type: 'ip'|'string'|'list'|'numeric', options?: [...] } }
  const [filterSchema, setFilterSchema] = useState(
    () => (chart.entry_schema && Object.keys(chart.entry_schema).length > 0)
      ? chart.entry_schema
      : null
  );
  // Per-chart filter values keyed by field name.
  const [chartFilters, setChartFilters] = useState({});

  // Auto-rerun when scope or chart-specific filter values change,
  // but only after the chart has been run at least once.
  const hasRun = useRef(false);
  useEffect(() => {
    if (hasRun.current) handleRun();
  }, [scope]);
  useEffect(() => {
    if (hasRun.current) handleRun();
  }, [JSON.stringify(chartFilters)]);

  function getTimeBounds() {
    if (!timeline?.length) return { timeStart: null, timeEnd: null };
    if (globalTimeBounds && !useCustomTime) return globalTimeBounds;
    const r = useCustomTime ? cardTimeRange : globalRange;
    const s = timeline[r[0]], e = timeline[r[1]];
    return { timeStart: s?.start_time ?? null, timeEnd: e?.end_time ?? null };
  }

  async function handleRun() {
    for (const p of chart.params || []) {
      if (p.required && !values[p.name]?.trim()) {
        setError(`"${p.label}" is required`); return;
      }
    }
    setLoading(true); setError('');
    try {
      const { timeStart, timeEnd } = getTimeBounds();
      const filterOverrides = {};
      if (timeStart != null) filterOverrides._timeStart = timeStart;
      if (timeEnd   != null) filterOverrides._timeEnd   = timeEnd;
      if (scope === 'scoped') {
        const protoNames = toProtocolNames(filterCtx.enabledP, filterCtx.allProtocolKeysCount);
        if (protoNames) filterOverrides._filterProtocols = protoNames;
        if (filterCtx.search?.trim()) filterOverrides._filterSearch = filterCtx.search.trim();
        if (!filterCtx.includeIPv6) filterOverrides._filterIncludeIpv6 = false;
      } else {
        const enabledProtos = [...protocols];
        if (enabledProtos.length < filterCtx.protocolList.length) filterOverrides._filterProtocols = enabledProtos.join(',');
        if (search.trim()) filterOverrides._filterSearch = search.trim();
        if (!includeIpv6) filterOverrides._filterIncludeIpv6 = false;
      }

      // Build _filter_* params from per-chart filter values
      const filterParamOverrides = {};
      if (filterSchema) {
        for (const [field, spec] of Object.entries(filterSchema)) {
          if (spec.type === 'numeric') {
            const min = chartFilters[`${field}_min`];
            const max = chartFilters[`${field}_max`];
            if (min !== undefined && min !== '') filterParamOverrides[`_filter_${field}_min`] = min;
            if (max !== undefined && max !== '') filterParamOverrides[`_filter_${field}_max`] = max;
          } else {
            const val = chartFilters[field];
            if (val !== undefined && val !== '' && !(Array.isArray(val) && val.length === 0)) {
              filterParamOverrides[`_filter_${field}`] = Array.isArray(val) ? val.join(',') : val;
            }
          }
        }
      }

      let res;
      if (chart._isCustom) {
        res = await runCustomChart({ ...chart._customConfig, ...filterOverrides });
      } else {
        const payload = { ...values, ...filterOverrides, ...filterParamOverrides };
        res = await api(`${researchApiBase}/${chart.name}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      }
      hasRun.current = true;
      setFigure(res.figure);
      if (res.filter_schema && Object.keys(res.filter_schema).length > 0) {
        setFilterSchema(res.filter_schema);
      }
    } catch (e) {
      const msg = e.message || 'Chart computation failed';
      setError(msg.toLowerCase().includes('no capture') || msg.includes('404')
        ? 'No capture loaded — upload a pcap first.'
        : msg);
    } finally {
      setLoading(false);
    }
  }

  function toggleProtocol(proto) {
    setProtocols(prev => {
      const next = new Set(prev);
      next.has(proto) ? next.delete(proto) : next.add(proto);
      return next;
    });
  }

  const hasChartFilters = filterSchema && Object.keys(chartFilters).some(k => {
    const v = chartFilters[k];
    return v !== '' && v !== undefined && !(Array.isArray(v) && v.length === 0);
  });
  const hasCustomFilters = useCustomTime || protocols.size < filterCtx.protocolList.length || search.trim() || !includeIpv6 || hasChartFilters;

  const timeLabel = (() => {
    if (!timeline?.length) return null;
    const r = useCustomTime ? cardTimeRange : globalRange;
    const s = timeline[r[0]], e = timeline[r[1]];
    return s && e ? `${fTtime(s.start_time)} — ${fTtime(e.end_time)}` : null;
  })();

  const inOverlay = !onResize;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', ...(inOverlay ? { height: '100%' } : {}) }}>
      {/* Header */}
      <div style={{ padding: '8px 10px', borderBottom: '1px solid var(--bd)', display: 'flex', alignItems: 'flex-start', gap: 8, background: 'var(--bgP)', borderRadius: '8px 8px 0 0' }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--tx)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{chart.title}</div>
          <div style={{ fontSize: 9, color: 'var(--txD)', marginTop: 1, fontStyle: 'italic', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{chart.description}</div>
        </div>
        <div style={{ display: 'flex', gap: 3, flexShrink: 0, alignItems: 'center' }}>
          <ScopePill value={scope} onChange={setScope} />
          <button onClick={() => setFiltersOpen(v => !v)}
            style={{ fontSize: 9, padding: '2px 6px', borderRadius: 4, border: `1px solid ${hasCustomFilters ? 'var(--ac)' : 'var(--bd)'}`,
              background: hasCustomFilters ? 'rgba(88,166,255,.1)' : 'transparent',
              color: hasCustomFilters ? 'var(--ac)' : 'var(--txD)', cursor: 'pointer' }}>
            {filtersOpen ? '▲' : '▼'} filters{hasCustomFilters ? ' ●' : ''}
          </button>
          {onToggleWide && (
            <button onClick={onToggleWide} title={isWide ? 'Shrink to half row' : 'Expand to full row'}
              style={{ fontSize: 9, padding: '2px 6px', borderRadius: 4,
                border: `1px solid ${isWide ? 'var(--ac)' : 'var(--bd)'}`,
                background: isWide ? 'rgba(88,166,255,.1)' : 'transparent',
                color: isWide ? 'var(--ac)' : 'var(--txD)', cursor: 'pointer' }}>
              ⇔
            </button>
          )}
          {chart._isCustom && onEdit && (
            <button onClick={onEdit} title="Edit chart"
              style={{ width: 22, height: 22, borderRadius: 4, border: '1px solid var(--bd)', background: 'transparent', color: 'var(--txD)', cursor: 'pointer', fontSize: 11, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--acP)'; e.currentTarget.style.color = 'var(--acP)'; }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--bd)'; e.currentTarget.style.color = 'var(--txD)'; }}>
              ✎
            </button>
          )}
          <button onClick={onExpand} title="Expand"
            style={{ width: 22, height: 22, borderRadius: 4, border: '1px solid var(--bd)', background: 'transparent', color: 'var(--txD)', cursor: 'pointer', fontSize: 11, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--ac)'; e.currentTarget.style.color = 'var(--ac)'; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--bd)'; e.currentTarget.style.color = 'var(--txD)'; }}>
            ⤢
          </button>
          <button onClick={onRemove} title="Remove"
            style={{ width: 22, height: 22, borderRadius: 4, border: '1px solid var(--bd)', background: 'transparent', color: 'var(--txD)', cursor: 'pointer', fontSize: 11, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--acR)'; e.currentTarget.style.color = 'var(--acR)'; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--bd)'; e.currentTarget.style.color = 'var(--txD)'; }}>
            ✕
          </button>
        </div>
      </div>

      {/* Filter drawer */}
      {filtersOpen && (
        <div style={{ padding: '8px 10px', borderBottom: '1px solid var(--bd)', background: '#0c0d12', display: 'flex', flexDirection: 'column', gap: 8 }}>
          {/* Time range */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <label style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', minWidth: 60 }}>Time</label>
            <button className={'btn' + (useCustomTime ? ' on' : '')}
              onClick={() => setUseCustomTime(v => !v)}
              style={{ fontSize: 9, padding: '1px 6px' }}>
              {useCustomTime ? 'custom' : 'global'}
            </button>
            {timeLabel && <span style={{ fontSize: 9, color: useCustomTime ? 'var(--ac)' : 'var(--txD)', fontFamily: 'var(--fn)' }}>{timeLabel}</span>}
          </div>
          {useCustomTime && timeline?.length > 1 && (
            <div style={{ paddingLeft: 68 }}>
              <Sparkline data={timeline} width={300} height={18} activeRange={cardTimeRange} />
              <div style={{ display: 'flex', gap: 4, alignItems: 'center', marginTop: 4 }}>
                <span style={{ fontSize: 9, color: 'var(--txD)', minWidth: 28 }}>Start</span>
                <input type="range" min={0} max={timeline.length - 1} value={cardTimeRange[0]}
                  onChange={e => { const v = +e.target.value; setCardTimeRange([v, Math.max(v, cardTimeRange[1])]); }}
                  style={{ flex: 1 }} />
              </div>
              <div style={{ display: 'flex', gap: 4, alignItems: 'center', marginTop: 2 }}>
                <span style={{ fontSize: 9, color: 'var(--txD)', minWidth: 28 }}>End</span>
                <input type="range" min={0} max={timeline.length - 1} value={cardTimeRange[1]}
                  onChange={e => { const v = +e.target.value; setCardTimeRange([Math.min(cardTimeRange[0], v), v]); }}
                  style={{ flex: 1 }} />
              </div>
            </div>
          )}

          {/* Protocol chips / Search / IPv6 — hidden for charts with entry_schema
              (chart filters cover this; stream-level narrowing is redundant) */}
          {!filterSchema && (<>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
              <label style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', minWidth: 60 }}>Protocols</label>
              {filterCtx.protocolList.map(proto => (
                <button key={proto}
                  onClick={() => toggleProtocol(proto)}
                  style={{ fontSize: 9, padding: '1px 6px', borderRadius: 10,
                    border: `1px solid ${protocols.has(proto) ? 'var(--ac)' : 'var(--bd)'}`,
                    background: protocols.has(proto) ? 'rgba(88,166,255,.1)' : 'transparent',
                    color: protocols.has(proto) ? 'var(--ac)' : 'var(--txD)',
                    cursor: 'pointer' }}>
                  {proto}
                </button>
              ))}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <label style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', minWidth: 60 }}>Search</label>
              <input className="inp"
                style={{ fontSize: 10, width: 160 }}
                placeholder="ip, port, protocol…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleRun()}
              />
              <button
                onClick={() => setIncludeIpv6(v => !v)}
                style={{ fontSize: 9, padding: '1px 6px', borderRadius: 10,
                  border: `1px solid ${includeIpv6 ? 'var(--ac)' : 'var(--bd)'}`,
                  background: includeIpv6 ? 'rgba(88,166,255,.1)' : 'transparent',
                  color: includeIpv6 ? 'var(--ac)' : 'var(--txD)',
                  cursor: 'pointer' }}>
                IPv6
              </button>
            </div>
          </>)}

          {/* Per-chart data filters — rendered from filterSchema detected on first run */}
          {filterSchema && Object.keys(filterSchema).length > 0 && (
            <>
              <div style={{ borderTop: '1px solid var(--bd)', marginTop: 2, paddingTop: 6 }}>
                <span style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em' }}>
                  Chart filters
                </span>
              </div>
              {Object.entries(filterSchema).map(([field, spec]) => (
                <div key={field} style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <label style={{ fontSize: 9, color: 'var(--txM)', minWidth: 60, textTransform: 'lowercase' }}>
                    {field.replace(/_/g, ' ')}
                  </label>

                  {/* ip / string → text input */}
                  {(spec.type === 'ip' || spec.type === 'string') && (
                    <input className="inp"
                      style={{ fontSize: 10, width: 160 }}
                      placeholder={spec.type === 'ip' ? 'e.g. 192.168.1' : 'contains…'}
                      value={chartFilters[field] || ''}
                      onChange={e => setChartFilters(prev => ({ ...prev, [field]: e.target.value }))}
                    />
                  )}

                  {/* numeric → min / max */}
                  {spec.type === 'numeric' && (
                    <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                      <input className="inp" type="number"
                        style={{ fontSize: 10, width: 70 }}
                        placeholder="min"
                        value={chartFilters[`${field}_min`] || ''}
                        onChange={e => setChartFilters(prev => ({ ...prev, [`${field}_min`]: e.target.value }))}
                      />
                      <span style={{ fontSize: 9, color: 'var(--txD)' }}>–</span>
                      <input className="inp" type="number"
                        style={{ fontSize: 10, width: 70 }}
                        placeholder="max"
                        value={chartFilters[`${field}_max`] || ''}
                        onChange={e => setChartFilters(prev => ({ ...prev, [`${field}_max`]: e.target.value }))}
                      />
                    </div>
                  )}

                  {/* list → chip multi-select */}
                  {spec.type === 'list' && (spec.options || []).map(opt => {
                    const selected = (chartFilters[field] || []);
                    const isOn = selected.includes(opt);
                    return (
                      <button key={opt}
                        onClick={() => setChartFilters(prev => {
                          const cur = prev[field] || [];
                          return {
                            ...prev,
                            [field]: isOn ? cur.filter(v => v !== opt) : [...cur, opt],
                          };
                        })}
                        style={{ fontSize: 9, padding: '1px 6px', borderRadius: 10,
                          border: `1px solid ${isOn ? 'var(--ac)' : 'var(--bd)'}`,
                          background: isOn ? 'rgba(88,166,255,.1)' : 'transparent',
                          color: isOn ? 'var(--ac)' : 'var(--txD)',
                          cursor: 'pointer' }}>
                        {opt}
                      </button>
                    );
                  })}
                </div>
              ))}
            </>
          )}
        </div>
      )}

      {/* Params row */}
      {(chart.params || []).length > 0 && (
        <div style={{ padding: '6px 10px', borderBottom: '1px solid var(--bd)', background: '#0a0b0f', display: 'flex', alignItems: 'flex-end', gap: 8, flexWrap: 'wrap' }}>
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
            style={{ marginBottom: 1, padding: '4px 14px', fontSize: 11,
              background: loading ? 'transparent' : 'rgba(88,166,255,.1)',
              borderColor: 'var(--ac)', color: 'var(--ac)', opacity: loading ? 0.5 : 1 }}>
            {loading ? 'Running…' : 'Run'}
          </button>
        </div>
      )}

      {/* No-param run row */}
      {(chart.params || []).length === 0 && (
        <div style={{ padding: '6px 10px', borderBottom: '1px solid var(--bd)', background: '#0a0b0f', display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 9, color: 'var(--txD)', fontStyle: 'italic', flex: 1 }}>
            {chart._isCustom
              ? `${chart._customConfig?.source || ''} · ${chart._customConfig?.chart_type || ''} · ${chart._customConfig?.x_field || ''}${chart._customConfig?.y_field ? ' vs ' + chart._customConfig.y_field : ''}`
              : 'No parameters'}
          </span>
          <button className="btn" onClick={handleRun} disabled={loading}
            style={{ padding: '4px 14px', fontSize: 11,
              background: loading ? 'transparent' : 'rgba(88,166,255,.1)',
              borderColor: 'var(--ac)', color: 'var(--ac)', opacity: loading ? 0.5 : 1 }}>
            {loading ? 'Running…' : 'Run'}
          </button>
        </div>
      )}

      {/* Chart */}
      <div
        onWheel={e => e.stopPropagation()}
        style={{ background: 'var(--bg)', overflowY: 'auto', minHeight: 0,
          ...(inOverlay ? { flex: 1, display: 'flex', flexDirection: 'column' } : { height: cardHeight || DEFAULT_CARD_HEIGHT }) }}>
        <ChartErrorBoundary>
          <PlotlyChart figure={figure} loading={loading} error={error} isWide={isWide} fillHeight={inOverlay} />
        </ChartErrorBoundary>
      </div>

      {/* Drag handle */}
      {onResize && (
        <div
          onMouseDown={handleResizeStart}
          style={{
            height: 8, cursor: 'ns-resize', background: 'var(--bg)',
            borderRadius: '0 0 8px 8px', display: 'flex', alignItems: 'center', justifyContent: 'center',
            borderTop: '1px solid var(--bd)',
          }}
        >
          <div style={{ width: 28, height: 2, borderRadius: 1, background: 'var(--bd)' }} />
        </div>
      )}
    </div>
  );
}

// ── ExpandedOverlay ───────────────────────────────────────────────────────────
export function ExpandedOverlay({ chart, investigatedIp, availableIps, globalTimeBounds, timeline, timeRange, bucketSec, setBucketSec, onClose }) {
  return (
    <div
      onWheel={e => e.stopPropagation()}
      style={{
        position: 'absolute', inset: 12, zIndex: 100,
        background: 'var(--bgP)', border: '1px solid var(--bdL)',
        borderRadius: 10, display: 'flex', flexDirection: 'column',
        boxShadow: '0 8px 40px rgba(0,0,0,.7)',
      }}>
      <div style={{ flex: 1, overflowY: 'auto', padding: 12, display: 'flex', flexDirection: 'column' }}>
        <PlacedCard
          chart={chart}
          investigatedIp={investigatedIp}
          availableIps={availableIps}
          globalTimeBounds={globalTimeBounds}
          timeline={timeline}
          timeRange={timeRange}
          bucketSec={bucketSec}
          setBucketSec={setBucketSec}
          isWide={true}
          onRemove={onClose}
          onExpand={onClose}
          slotId="expanded"
        />
      </div>
    </div>
  );
}
