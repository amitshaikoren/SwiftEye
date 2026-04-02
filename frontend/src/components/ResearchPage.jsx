import React, { useState, useEffect, useRef, useCallback } from 'react';
import { fetchResearchCharts, runResearchChart, fetchCustomChartSchema, runCustomChart } from '../api';
import { fTtime } from '../utils';
import Sparkline from './Sparkline';

// ── Custom chart localStorage persistence ─────────────────────────────────────
const CUSTOM_CHARTS_KEY = 'swifteye_custom_charts';

function loadSavedCustomCharts() {
  try {
    return JSON.parse(localStorage.getItem(CUSTOM_CHARTS_KEY) || '[]');
  } catch { return []; }
}

function saveCustomCharts(configs) {
  try { localStorage.setItem(CUSTOM_CHARTS_KEY, JSON.stringify(configs)); } catch {}
}

// ── CustomChartBuilder modal ──────────────────────────────────────────────────
// Two-step wizard:
//   Step 1 — pick a data source (cards, greyed out if no data in capture)
//   Step 2 — map fields + pick chart type + set title
function CustomChartBuilder({ onSave, onClose, initial }) {
  const [schema, setSchema] = useState(null);
  const [schemaErr, setSchemaErr] = useState('');
  const [step, setStep] = useState(initial?.source ? 2 : 1);

  // Step 1
  const [source, setSource] = useState(initial?.source || '');

  // Step 2
  const CHART_TYPES = ['scatter', 'bar', 'histogram'];
  const [chartType, setChartType]     = useState(initial?.chart_type || 'scatter');
  const [xField, setXField]           = useState(initial?.x_field || '');
  const [yField, setYField]           = useState(initial?.y_field || '');
  const [colorField, setColorField]   = useState(initial?.color_field || '');
  const [sizeField, setSizeField]     = useState(initial?.size_field || '');
  const [hoverFields, setHoverFields] = useState(initial?.hover_fields || []);
  const [title, setTitle]             = useState(initial?.title || '');
  const [validErr, setValidErr]       = useState('');

  useEffect(() => {
    fetchCustomChartSchema()
      .then(d => setSchema(d.sources || []))
      .catch(e => setSchemaErr(e.message || 'Failed to load schema'));
  }, []);

  const sourceInfo = schema?.find(s => s.id === source);
  const fields = sourceInfo?.fields || [];

  function handleSourcePick(src) {
    setSource(src);
    setXField(''); setYField(''); setColorField(''); setSizeField('');
    setHoverFields([]);
    setTitle(schema?.find(s => s.id === src)?.label || src);
    setStep(2);
  }

  function toggleHover(f) {
    setHoverFields(prev => prev.includes(f) ? prev.filter(x => x !== f) : [...prev, f]);
  }

  function handleSave() {
    if (!xField) { setValidErr('X axis field is required.'); return; }
    if (chartType !== 'histogram' && !yField) { setValidErr('Y axis field is required.'); return; }
    setValidErr('');
    onSave({
      source,
      chart_type:   chartType,
      x_field:      xField,
      y_field:      yField,
      color_field:  colorField || null,
      size_field:   sizeField  || null,
      hover_fields: hoverFields,
      title:        title || 'Custom Chart',
    });
  }

  const SOURCE_ICONS = {
    packets: '📦', sessions: '🔗', dns: '🌐', http: '🕸', tls: '🔒',
    tcp: '⚡', dhcp: '🏠', arp: '📡', icmp: '📣',
  };

  return (
    <div
      style={{ position: 'fixed', inset: 0, zIndex: 400, background: 'rgba(0,0,0,.65)',
        display: 'flex', alignItems: 'center', justifyContent: 'center' }}
      onClick={onClose}
    >
      <div
        style={{ background: 'var(--bgP)', border: '1px solid var(--bdL)', borderRadius: 10,
          width: 500, maxHeight: '85vh', overflow: 'hidden', display: 'flex', flexDirection: 'column',
          boxShadow: '0 8px 40px rgba(0,0,0,.7)' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--bd)', display: 'flex', alignItems: 'center', gap: 8 }}>
          {step === 2 && (
            <button onClick={() => setStep(1)}
              style={{ background: 'transparent', border: 'none', color: 'var(--txD)', cursor: 'pointer', fontSize: 14, padding: '0 4px', lineHeight: 1 }}>
              ←
            </button>
          )}
          <span style={{ flex: 1, fontSize: 13, fontWeight: 600, color: 'var(--tx)' }}>
            {step === 1 ? 'Custom chart — pick a data source' : `Custom chart — ${sourceInfo?.label || source}`}
          </span>
          <button onClick={onClose}
            style={{ background: 'transparent', border: 'none', color: 'var(--txD)', cursor: 'pointer', fontSize: 14 }}>✕</button>
        </div>

        <div style={{ overflowY: 'auto', flex: 1, padding: '14px 16px' }}>
          {schemaErr && (
            <div style={{ padding: '8px 10px', background: 'rgba(248,81,73,.08)', border: '1px solid rgba(248,81,73,.2)',
              borderRadius: 6, color: 'var(--acR)', fontSize: 11, marginBottom: 12 }}>
              {schemaErr}
            </div>
          )}

          {/* ── Step 1: source picker ── */}
          {step === 1 && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {!schema && !schemaErr && (
                <div style={{ gridColumn: '1/-1', color: 'var(--txD)', fontSize: 11, textAlign: 'center', padding: 20 }}>
                  Loading sources…
                </div>
              )}
              {(schema || []).map(src => {
                const active = src.has_data;
                return (
                  <div key={src.id}
                    onClick={() => active && handleSourcePick(src.id)}
                    style={{
                      padding: '10px 12px', borderRadius: 7, border: `1px solid ${active ? 'var(--bd)' : 'rgba(255,255,255,.05)'}`,
                      background: active ? 'var(--bg)' : 'rgba(255,255,255,.02)',
                      cursor: active ? 'pointer' : 'default',
                      opacity: active ? 1 : 0.4,
                      transition: 'border-color .12s',
                    }}
                    onMouseEnter={e => active && (e.currentTarget.style.borderColor = 'var(--ac)')}
                    onMouseLeave={e => active && (e.currentTarget.style.borderColor = 'var(--bd)')}
                  >
                    <div style={{ fontSize: 16, marginBottom: 4 }}>{SOURCE_ICONS[src.id] || '📊'}</div>
                    <div style={{ fontSize: 12, fontWeight: 600, color: active ? 'var(--tx)' : 'var(--txD)' }}>{src.label}</div>
                    <div style={{ fontSize: 9, color: 'var(--txD)', marginTop: 2 }}>
                      {active ? `${src.fields.length} fields` : 'no data in capture'}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* ── Step 2: field mapping ── */}
          {step === 2 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

              {/* Chart type */}
              <div>
                <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 5 }}>Chart type</div>
                <div style={{ display: 'flex', gap: 6 }}>
                  {CHART_TYPES.map(ct => (
                    <button key={ct} onClick={() => setChartType(ct)}
                      style={{ fontSize: 10, padding: '3px 10px', borderRadius: 5,
                        border: `1px solid ${chartType === ct ? 'var(--ac)' : 'var(--bd)'}`,
                        background: chartType === ct ? 'rgba(88,166,255,.1)' : 'transparent',
                        color: chartType === ct ? 'var(--ac)' : 'var(--txM)', cursor: 'pointer' }}>
                      {ct.charAt(0).toUpperCase() + ct.slice(1)}
                    </button>
                  ))}
                </div>
              </div>

              {/* X axis */}
              <FieldSelect label="X axis *" value={xField} onChange={setXField} fields={fields} />

              {/* Y axis — hidden for histogram */}
              {chartType !== 'histogram' && (
                <FieldSelect label="Y axis *" value={yField} onChange={setYField} fields={fields} />
              )}

              {/* Colour */}
              <FieldSelect label="Colour by" value={colorField} onChange={setColorField} fields={fields} optional />

              {/* Size — scatter only */}
              {chartType === 'scatter' && (
                <FieldSelect label="Size by (numeric)" value={sizeField} onChange={setSizeField}
                  fields={fields.filter(f => f.type === 'numeric')} optional />
              )}

              {/* Hover fields */}
              <div>
                <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 5 }}>Hover fields</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                  {fields.map(f => {
                    const on = hoverFields.includes(f.name);
                    return (
                      <button key={f.name} onClick={() => toggleHover(f.name)}
                        style={{ fontSize: 9, padding: '2px 8px', borderRadius: 10,
                          border: `1px solid ${on ? 'var(--acP)' : 'var(--bd)'}`,
                          background: on ? 'rgba(163,113,247,.12)' : 'transparent',
                          color: on ? 'var(--acP)' : 'var(--txD)', cursor: 'pointer' }}>
                        {f.label}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Title */}
              <div>
                <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 4 }}>Chart title</div>
                <input className="inp" value={title} onChange={e => setTitle(e.target.value)}
                  placeholder="Custom Chart" style={{ width: '100%', fontSize: 12 }} />
              </div>

              {validErr && (
                <div style={{ color: 'var(--acR)', fontSize: 10 }}>{validErr}</div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        {step === 2 && (
          <div style={{ padding: '10px 16px', borderTop: '1px solid var(--bd)', display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <button onClick={onClose}
              style={{ fontSize: 11, padding: '4px 14px', borderRadius: 5, border: '1px solid var(--bd)',
                background: 'transparent', color: 'var(--txD)', cursor: 'pointer' }}>
              Cancel
            </button>
            <button onClick={handleSave}
              style={{ fontSize: 11, padding: '4px 14px', borderRadius: 5, border: '1px solid var(--ac)',
                background: 'rgba(88,166,255,.1)', color: 'var(--ac)', cursor: 'pointer' }}>
              Add to canvas
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// ── FieldSelect — labelled <select> for field mapping ─────────────────────────
function FieldSelect({ label, value, onChange, fields, optional }) {
  return (
    <div>
      <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 4 }}>
        {label}
      </div>
      <select
        className="inp"
        value={value}
        onChange={e => onChange(e.target.value)}
        style={{ width: '100%', fontSize: 11 }}
      >
        {optional && <option value="">— none —</option>}
        {!optional && <option value="">Select a field…</option>}
        {fields.map(f => (
          <option key={f.name} value={f.name}>{f.label} ({f.name})</option>
        ))}
      </select>
    </div>
  );
}

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

// ── PROTOCOLS available for filter chips ──────────────────────────────────────
const ALL_PROTOCOLS = ['TCP', 'UDP', 'DNS', 'TLS', 'HTTP', 'ICMP', 'ARP', 'DHCP'];
const DEFAULT_CARD_HEIGHT = 380;

// ── PlacedCard — a chart placed in a slot ─────────────────────────────────────
function PlacedCard({
  chart, investigatedIp, availableIps,
  globalTimeBounds,
  timeline, timeRange: globalRange, bucketSec, setBucketSec,
  isWide, onToggleWide,
  cardHeight, onResize,
  onRemove, onExpand, onEdit,
}) {
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
  // ── per-card filter state
  const [useCustomTime, setUseCustomTime] = useState(false);
  const [cardTimeRange, setCardTimeRange] = useState([0, Math.max(0, (timeline?.length ?? 1) - 1)]);
  const [protocols, setProtocols]     = useState(new Set(ALL_PROTOCOLS));
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

  const [figure, setFigure]   = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');

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
      const enabledProtos = [...protocols];
      const filterOverrides = {};
      if (timeStart != null) filterOverrides._timeStart = timeStart;
      if (timeEnd   != null) filterOverrides._timeEnd   = timeEnd;
      if (enabledProtos.length < ALL_PROTOCOLS.length) filterOverrides._filterProtocols = enabledProtos.join(',');
      if (search.trim()) filterOverrides._filterSearch = search.trim();
      if (!includeIpv6)  filterOverrides._filterIncludeIpv6 = false;

      let res;
      if (chart._isCustom) {
        res = await runCustomChart({ ...chart._customConfig, ...filterOverrides });
      } else {
        const payload = { ...values, ...filterOverrides };
        res = await runResearchChart(chart.name, payload);
      }
      setFigure(res.figure);
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

  const hasCustomFilters = useCustomTime || protocols.size < ALL_PROTOCOLS.length || search.trim() || !includeIpv6;

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
        <div style={{ display: 'flex', gap: 3, flexShrink: 0 }}>
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
              style={{ fontSize: 8, padding: '1px 6px' }}>
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

          {/* Protocol chips */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
            <label style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', minWidth: 60 }}>Protocols</label>
            {ALL_PROTOCOLS.map(proto => (
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

          {/* Search + IPv6 */}
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
function ExpandedOverlay({ chart, investigatedIp, availableIps, globalTimeBounds, timeline, timeRange, bucketSec, setBucketSec, onClose }) {
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
        />
      </div>
    </div>
  );
}

// ── EmptySlot ─────────────────────────────────────────────────────────────────
function EmptySlot({ onDrop, onClick, dragOverId, slotId }) {
  const isOver = dragOverId === slotId;
  return (
    <div
      onClick={onClick}
      onDragOver={e => { e.preventDefault(); onDrop('over', slotId); }}
      onDragLeave={() => onDrop('leave', slotId)}
      onDrop={e => { e.preventDefault(); onDrop('drop', slotId); }}
      style={{
        height: DEFAULT_CARD_HEIGHT, borderRadius: 8,
        border: `1px dashed ${isOver ? 'var(--ac)' : 'var(--bd)'}`,
        background: isOver ? 'rgba(88,166,255,.04)' : '#0a0b0f',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        cursor: 'pointer', transition: 'border-color .15s, background .15s',
      }}
    >
      <div style={{ textAlign: 'center', pointerEvents: 'none', userSelect: 'none' }}>
        <div style={{ fontSize: 20, color: 'var(--bd)', marginBottom: 4 }}>+</div>
        <div style={{ fontSize: 10, color: 'var(--bdL)' }}>Drag a chart here<br/>or click to pick</div>
      </div>
    </div>
  );
}

// ── ChartPicker modal ─────────────────────────────────────────────────────────
function ChartPicker({ charts, onPick, onClose, onCustom }) {
  const categories = ['host', 'session', 'capture', 'alerts'];
  const grouped = {};
  categories.forEach(c => { grouped[c] = []; });
  charts.forEach(ch => { (grouped[ch._category] || grouped['capture']).push(ch); });

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 300,
      background: 'rgba(0,0,0,.6)', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div style={{
        background: 'var(--bgP)', border: '1px solid var(--bdL)', borderRadius: 10,
        width: 420, maxHeight: '70vh', overflow: 'hidden', display: 'flex', flexDirection: 'column',
        boxShadow: '0 8px 40px rgba(0,0,0,.7)',
      }} onClick={e => e.stopPropagation()}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--bd)', display: 'flex', alignItems: 'center' }}>
          <span style={{ flex: 1, fontSize: 13, fontWeight: 600, color: 'var(--tx)' }}>Pick a chart</span>
          <button className="btn" onClick={onClose} style={{ fontSize: 10, padding: '2px 8px' }}>✕</button>
        </div>
        <div style={{ overflowY: 'auto', padding: '10px 12px' }}>
          {/* Custom chart option at top */}
          {onCustom && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: '.08em', color: 'var(--acP)', marginBottom: 6 }}>Custom</div>
              <div onClick={onCustom}
                style={{ padding: '8px 10px', borderRadius: 6, border: '1px dashed var(--acP)', background: 'rgba(163,113,247,.05)',
                  marginBottom: 6, cursor: 'pointer' }}
                onMouseEnter={e => e.currentTarget.style.background = 'rgba(163,113,247,.12)'}
                onMouseLeave={e => e.currentTarget.style.background = 'rgba(163,113,247,.05)'}>
                <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--acP)' }}>✦ Build custom chart</div>
                <div style={{ fontSize: 10, color: 'var(--txD)', marginTop: 2 }}>Pick a data source and map fields to axes</div>
              </div>
            </div>
          )}
          {categories.map(cat => {
            const items = grouped[cat];
            if (!items?.length) return null;
            return (
              <div key={cat} style={{ marginBottom: 14 }}>
                <div style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: '.08em', color: CAT_COLORS[cat], marginBottom: 6 }}>
                  {CAT_LABELS[cat]}
                </div>
                {items.map(ch => (
                  <div key={ch.name} onClick={() => onPick(ch)}
                    style={{ padding: '8px 10px', borderRadius: 6, border: '1px solid var(--bd)', background: 'var(--bg)',
                      marginBottom: 6, cursor: 'pointer', transition: 'border-color .12s' }}
                    onMouseEnter={e => e.currentTarget.style.borderColor = CAT_COLORS[ch._category]}
                    onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--bd)'}>
                    <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--tx)' }}>{ch.title}</div>
                    <div style={{ fontSize: 10, color: 'var(--txD)', marginTop: 2 }}>{ch.description}</div>
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ── Category metadata ─────────────────────────────────────────────────────────
const CAT_LABELS  = { host: 'Host', session: 'Session', capture: 'Capture', alerts: 'Alerts', other: 'Other' };
const CAT_COLORS  = { host: 'var(--acG)', session: 'var(--acP)', capture: 'var(--ac)', alerts: 'var(--acR)', other: 'var(--fg3)' };
const CAT_ORDER   = ['host', 'session', 'capture', 'alerts', 'other'];
const KNOWN_CATS  = new Set(CAT_ORDER);

// Use the category declared by the backend. Falls back to a heuristic for
// custom charts (which are client-side objects with no backend category field),
// and to "other" for any unrecognised value a future chart might declare.
function inferCategory(chart) {
  if (chart._isCustom) return 'capture';
  const cat = chart.category;
  if (cat && KNOWN_CATS.has(cat)) return cat;
  return 'other';
}

// ── SlotGrid — flat grid of slots, no category labels ─────────────────────────
function SlotGrid({ slots, onSlotDrop, onSlotClick, onRemove, onExpand, onToggleWide, onResize, onEditCustom, dragOverId, investigatedIp, availableIps, globalTimeBounds, timeline, timeRange, bucketSec, setBucketSec }) {
  // Flatten all category slots into one list, preserving id/chart/wide
  const allSlots = CAT_ORDER.flatMap(cat => slots[cat] || []);

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
      {allSlots.map(slot => {
        const isWide = slot.wide;
        return (
          <div key={slot.id} style={{ gridColumn: isWide ? '1 / -1' : 'auto' }}>
            {slot.chart ? (
              <div style={{ border: '1px solid var(--bd)', borderRadius: 8, overflow: 'hidden', background: 'var(--bgP)' }}>
                <PlacedCard
                  chart={slot.chart}
                  investigatedIp={investigatedIp}
                  availableIps={availableIps}
                  globalTimeBounds={globalTimeBounds}
                  timeline={timeline}
                  timeRange={timeRange}
                  bucketSec={bucketSec}
                  setBucketSec={setBucketSec}
                  isWide={isWide}
                  onToggleWide={() => onToggleWide(slot.id)}
                  cardHeight={slot.height}
                  onResize={h => onResize(slot.id, h)}
                  onRemove={() => onRemove(slot.id)}
                  onExpand={() => onExpand(slot.chart)}
                  onEdit={slot.chart._isCustom ? () => onEditCustom(slot.id, slot.chart) : undefined}
                />
              </div>
            ) : (
              <EmptySlot
                slotId={slot.id}
                dragOverId={dragOverId}
                onDrop={onSlotDrop}
                onClick={() => onSlotClick(slot.id)}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── PaletteCategory — collapsible category section in the right palette ───────
function PaletteCategory({ category, charts, onDragStart, onDragEnd }) {
  const [collapsed, setCollapsed] = useState(false);
  const color = CAT_COLORS[category];
  const label = CAT_LABELS[category];
  const isAlerts = category === 'alerts';

  return (
    <div style={{ marginBottom: 14 }}>
      <div
        onClick={() => setCollapsed(v => !v)}
        style={{ display: 'flex', alignItems: 'center', gap: 4, margin: '6px 0 4px 2px', cursor: 'pointer', userSelect: 'none' }}
      >
        <span style={{ fontSize: 8, textTransform: 'uppercase', letterSpacing: '.08em', color, flex: 1 }}>{label}</span>
        <span style={{ fontSize: 8, color: 'var(--txD)' }}>{collapsed ? '▶' : '▼'}</span>
      </div>
      {!collapsed && (
        isAlerts ? (
          <div style={{ fontSize: 9, color: 'var(--txD)', fontStyle: 'italic', padding: '4px 6px' }}>Coming soon</div>
        ) : (
          <>
            {charts.map(chart => (
              <div
                key={chart.name}
                draggable
                onDragStart={() => onDragStart(chart)}
                onDragEnd={onDragEnd}
                style={{
                  padding: '6px 8px', borderRadius: 6, border: '1px solid var(--bd)',
                  background: 'var(--bgP)', marginBottom: 5, cursor: 'grab',
                  transition: 'border-color .12s',
                }}
                onMouseEnter={e => e.currentTarget.style.borderColor = color}
                onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--bd)'}
              >
                <div style={{ fontSize: 11, fontWeight: 500, color: 'var(--tx)' }}>{chart.title}</div>
                <div style={{ fontSize: 9, color: 'var(--txD)', marginTop: 2, lineHeight: 1.3 }}>{chart.description}</div>
              </div>
            ))}
          </>
        )
      )}
    </div>
  );
}

// ── ResearchPage ──────────────────────────────────────────────────────────────
export default function ResearchPage({
  investigatedIp = '',
  searchIp = '',
  seqAckSessionId = '',
  availableIps = [],
  timeline = [], timeRange = [0, 0], setTimeRange,
  bucketSec = 15, setBucketSec,
}) {
  const effectiveIp = investigatedIp || searchIp;

  const [allCharts, setAllCharts] = useState([]);
  const [loadErr, setLoadErr]     = useState('');

  const [slots, setSlots] = useState({
    host:    [{ id: 'host-0', chart: null, wide: false, height: null }, { id: 'host-1', chart: null, wide: false, height: null }],
    session: [{ id: 'session-0', chart: null, wide: false, height: null }, { id: 'session-1', chart: null, wide: false, height: null }],
    capture: [{ id: 'capture-0', chart: null, wide: false, height: null }, { id: 'capture-1', chart: null, wide: false, height: null }],
    alerts:  [],
  });

  const [draggedChart, setDraggedChart] = useState(null);
  const [dragOverId, setDragOverId]     = useState(null);
  const [pickerSlotId, setPickerSlotId] = useState(null);
  const [expandedChart, setExpandedChart] = useState(null);
  const [paletteOpen, setPaletteOpen]   = useState(true);
  const slotCounter = useRef(100); // start above default slot IDs to avoid collisions

  // ── Custom chart builder state ────────────────────────────────────────────
  // builderState: null (closed) | { mode: 'create', slotId } | { mode: 'edit', slotId, initial }
  const [builderState, setBuilderState] = useState(null);

  const timeRangeRef = useRef(timeRange);
  const timelineRef  = useRef(timeline);
  useEffect(() => { timeRangeRef.current = timeRange; }, [timeRange]);
  useEffect(() => { timelineRef.current  = timeline;  }, [timeline]);

  function globalTimeBounds() {
    const tl = timelineRef.current;
    const tr = timeRangeRef.current;
    if (!tl.length) return { timeStart: null, timeEnd: null };
    return { timeStart: tl[tr[0]]?.start_time ?? null, timeEnd: tl[tr[1]]?.end_time ?? null };
  }

  useEffect(() => {
    fetchResearchCharts()
      .then(d => {
        const charts = (d.charts || [])
          .filter(c => c.name !== 'session_gantt')
          .map(c => ({ ...c, _category: inferCategory(c) }));
        setAllCharts(charts);

        if (seqAckSessionId) {
          const seqChart = charts.find(c => c.name === 'seq_ack_timeline');
          if (seqChart) {
            setSlots(prev => placeChart(prev, 'session-0', seqChart));
          }
        }
      })
      .catch(e => setLoadErr(e.message));
  }, []);

  function placeChart(prevSlots, slotId, chart) {
    const next = {};
    for (const [cat, arr] of Object.entries(prevSlots)) {
      next[cat] = arr.map(s => s.id === slotId ? { ...s, chart } : s);
    }
    return next;
  }

  // Build a chart object from a custom config (returned by CustomChartBuilder)
  function makeCustomChart(config) {
    return {
      name:           `custom_${Date.now()}`,
      title:          config.title || 'Custom Chart',
      description:    `${config.source} · ${config.chart_type} · ${config.x_field}${config.y_field ? ' vs ' + config.y_field : ''}`,
      params:         [],
      _isCustom:      true,
      _customConfig:  config,
      _category:      'capture',
    };
  }

  // Save custom chart config to localStorage
  function persistCustomConfig(config) {
    const saved = loadSavedCustomCharts();
    const existing = saved.findIndex(c => c._id === config._id);
    if (existing >= 0) saved[existing] = config;
    else saved.push(config);
    saveCustomCharts(saved);
  }

  function removeCustomConfig(id) {
    const saved = loadSavedCustomCharts().filter(c => c._id !== id);
    saveCustomCharts(saved);
  }

  function handleBuilderSave(config) {
    const bs = builderState;
    setBuilderState(null);
    if (!bs) return;
    // Give it a stable ID for localStorage keying
    const configWithId = { ...config, _id: bs.initial?._id || `cc_${Date.now()}` };
    persistCustomConfig(configWithId);
    const chart = makeCustomChart(configWithId);
    if (bs.mode === 'create') {
      // Place into a new slot if no target, or into specific slot from picker
      const targetSlotId = bs.slotId;
      if (targetSlotId) {
        setSlots(prev => placeChart(prev, targetSlotId, chart));
      } else {
        // Add new slot and place
        const id = `slot-${slotCounter.current++}`;
        setSlots(prev => ({
          ...prev,
          capture: [...prev.capture, { id, chart, wide: false, height: null }],
        }));
      }
    } else {
      // Edit: replace existing slot's chart in-place
      setSlots(prev => placeChart(prev, bs.slotId, chart));
    }
  }

  function handleEditCustom(slotId, existingChart) {
    setBuilderState({ mode: 'edit', slotId, initial: existingChart._customConfig });
  }

  function addSlot() {
    const id = `slot-${slotCounter.current++}`;
    setSlots(prev => ({ ...prev, capture: [...prev.capture, { id, chart: null, wide: false, height: null }] }));
  }

  function handleResize(slotId, height) {
    setSlots(prev => {
      const next = {};
      for (const [cat, arr] of Object.entries(prev)) {
        next[cat] = arr.map(s => s.id === slotId ? { ...s, height } : s);
      }
      return next;
    });
  }

  function handleSlotDrop(action, slotId) {
    if (action === 'over')  { setDragOverId(slotId); return; }
    if (action === 'leave') { setDragOverId(null); return; }
    if (action === 'drop' && draggedChart) {
      setSlots(prev => placeChart(prev, slotId, draggedChart));
      setDraggedChart(null);
      setDragOverId(null);
    }
  }

  function handleSlotClick(slotId) {
    setPickerSlotId(slotId);
  }

  function handlePickerPick(chart) {
    setSlots(prev => placeChart(prev, pickerSlotId, chart));
    setPickerSlotId(null);
  }

  function handleRemove(slotId) {
    setSlots(prev => {
      const next = {};
      for (const [cat, arr] of Object.entries(prev)) {
        next[cat] = arr.map(s => s.id === slotId ? { ...s, chart: null } : s);
      }
      return next;
    });
  }

  function handleToggleWide(slotId) {
    setSlots(prev => {
      const next = {};
      for (const [cat, arr] of Object.entries(prev)) {
        next[cat] = arr.map(s => {
          if (s.id !== slotId) return s;
          const newWide = !s.wide;
          return { ...s, wide: newWide, height: newWide ? s.height : null };
        });
      }
      return next;
    });
  }

  function paletteCharts(cat) {
    return allCharts.filter(c => c._category === cat);
  }

  const timeLabel = (() => {
    if (!timeline.length) return 'Full capture';
    const s = timeline[timeRange[0]], e = timeline[timeRange[1]];
    return s && e ? `${fTtime(s.start_time)} — ${fTtime(e.end_time)}` : 'Full capture';
  })();
  const isFullRange = !timeline.length || (timeRange[0] === 0 && timeRange[1] === timeline.length - 1);

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden', position: 'relative', background: 'var(--bg)' }}>

      {/* Main canvas */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px 20px', display: 'flex', flexDirection: 'column', gap: 24 }}>

        {/* Global time scope */}
        {timeline.length > 1 && (
          <div style={{ background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 8, padding: '10px 14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="var(--txD)" strokeWidth="2">
                  <circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>
                </svg>
                <span style={{ fontSize: 9, color: 'var(--txM)', textTransform: 'uppercase', letterSpacing: '.06em' }}>Global time scope</span>
                {[5, 15, 30, 60].map(s => (
                  <button key={s} className={'btn' + (bucketSec === s ? ' on' : '')}
                    onClick={() => setBucketSec(s)} style={{ padding: '1px 5px', fontSize: 8 }}>{s}s</button>
                ))}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 9, color: isFullRange ? 'var(--txD)' : 'var(--ac)', fontFamily: 'var(--fn)' }}>{timeLabel}</span>
                {!isFullRange && (
                  <button className="btn" style={{ fontSize: 8, padding: '1px 6px' }}
                    onClick={() => setTimeRange([0, timeline.length - 1])}>Reset</button>
                )}
              </div>
            </div>
            <Sparkline data={timeline} width={600} height={20} activeRange={timeRange} />
            <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 6 }}>
              <span style={{ fontSize: 9, color: 'var(--txD)', minWidth: 30 }}>Start</span>
              <input type="range" min={0} max={timeline.length - 1} value={timeRange[0]}
                onChange={e => { const v = +e.target.value; setTimeRange([v, Math.max(v, timeRange[1])]); }}
                style={{ flex: 1 }} />
            </div>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 2 }}>
              <span style={{ fontSize: 9, color: 'var(--txD)', minWidth: 30 }}>End</span>
              <input type="range" min={0} max={timeline.length - 1} value={timeRange[1]}
                onChange={e => { const v = +e.target.value; setTimeRange([Math.min(timeRange[0], v), v]); }}
                style={{ flex: 1 }} />
            </div>
            <div style={{ marginTop: 6, fontSize: 9, color: 'var(--txD)' }}>
              Per-card filters override this scope. Cards set to "global" inherit this range.
            </div>
          </div>
        )}

        {loadErr && (
          <div style={{ padding: '10px 14px', background: 'rgba(248,81,73,.08)', border: '1px solid rgba(248,81,73,.2)', borderRadius: 8, color: 'var(--acR)', fontSize: 11 }}>
            Failed to load charts: {loadErr}
          </div>
        )}

        {/* Flat slot grid — no category labels */}
        <SlotGrid
          slots={slots}
          onSlotDrop={handleSlotDrop}
          onSlotClick={handleSlotClick}
          onRemove={handleRemove}
          onExpand={setExpandedChart}
          onToggleWide={handleToggleWide}
          onResize={handleResize}
          onEditCustom={handleEditCustom}
          dragOverId={dragOverId}
          investigatedIp={effectiveIp}
          availableIps={availableIps}
          globalTimeBounds={globalTimeBounds()}
          timeline={timeline}
          timeRange={timeRange}
          bucketSec={bucketSec}
          setBucketSec={setBucketSec}
        />
        <div style={{ display: 'flex', justifyContent: 'center' }}>
          <button className="btn" onClick={addSlot}
            style={{ fontSize: 10, padding: '5px 20px', color: 'var(--txD)', borderColor: 'var(--bd)' }}>
            + add slot
          </button>
        </div>
      </div>

      {/* Right palette */}
      <div style={{
        width: paletteOpen ? 200 : 28, flexShrink: 0, borderLeft: '1px solid var(--bd)',
        background: '#0a0b0f', display: 'flex', flexDirection: 'column', overflow: 'hidden',
        transition: 'width .15s ease',
      }}>
        {/* Palette header */}
        <div style={{ padding: '10px 8px 6px', display: 'flex', alignItems: 'center', borderBottom: '1px solid var(--bd)', flexShrink: 0, gap: 6 }}>
          {paletteOpen && (
            <span style={{ flex: 1, fontSize: 9, textTransform: 'uppercase', letterSpacing: '.1em', color: 'var(--txD)' }}>Charts</span>
          )}
          <button
            onClick={() => setPaletteOpen(v => !v)}
            title={paletteOpen ? 'Collapse palette' : 'Expand palette'}
            style={{ width: 18, height: 18, borderRadius: 3, border: '1px solid var(--bd)', background: 'transparent',
              color: 'var(--txD)', cursor: 'pointer', fontSize: 9, display: 'flex', alignItems: 'center', justifyContent: 'center',
              flexShrink: 0 }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--ac)'; e.currentTarget.style.color = 'var(--ac)'; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--bd)'; e.currentTarget.style.color = 'var(--txD)'; }}
          >
            {paletteOpen ? '›' : '‹'}
          </button>
        </div>

        {/* Palette content */}
        {paletteOpen && (
          <div style={{ flex: 1, overflowY: 'auto', padding: '8px 8px' }}>
            {/* Custom chart button — at top of palette */}
            <div style={{ marginBottom: 12 }}>
              <button
                onClick={() => setBuilderState({ mode: 'create', slotId: null })}
                style={{
                  width: '100%', padding: '7px 8px', borderRadius: 6, cursor: 'pointer',
                  border: '1px dashed var(--acP)', background: 'rgba(163,113,247,.06)',
                  color: 'var(--acP)', fontSize: 10, fontWeight: 600, textAlign: 'left',
                  display: 'flex', alignItems: 'center', gap: 6,
                }}
                onMouseEnter={e => { e.currentTarget.style.background = 'rgba(163,113,247,.14)'; }}
                onMouseLeave={e => { e.currentTarget.style.background = 'rgba(163,113,247,.06)'; }}
              >
                <span style={{ fontSize: 13 }}>✦</span> Custom chart
              </button>
            </div>
            {CAT_ORDER.map(cat => (
              <PaletteCategory
                key={cat}
                category={cat}
                charts={paletteCharts(cat)}
                onDragStart={setDraggedChart}
                onDragEnd={() => setDraggedChart(null)}
              />
            ))}
          </div>
        )}
      </div>

      {/* Chart picker modal */}
      {pickerSlotId && (
        <ChartPicker
          charts={allCharts}
          onPick={handlePickerPick}
          onClose={() => setPickerSlotId(null)}
          onCustom={() => {
            const sid = pickerSlotId;
            setPickerSlotId(null);
            setBuilderState({ mode: 'create', slotId: sid });
          }}
        />
      )}

      {/* Custom chart builder modal */}
      {builderState && (
        <CustomChartBuilder
          initial={builderState.initial || null}
          onSave={handleBuilderSave}
          onClose={() => setBuilderState(null)}
        />
      )}

      {/* Expanded overlay */}
      {expandedChart && (
        <ExpandedOverlay
          chart={expandedChart}
          investigatedIp={effectiveIp}
          availableIps={availableIps}
          globalTimeBounds={globalTimeBounds()}
          timeline={timeline}
          timeRange={timeRange}
          bucketSec={bucketSec}
          setBucketSec={setBucketSec}
          onClose={() => setExpandedChart(null)}
        />
      )}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
