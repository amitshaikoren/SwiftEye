import React, { useState, useEffect } from 'react';
import { fetchCustomChartSchema } from '../../api';

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

// ── CustomChartBuilder modal ──────────────────────────────────────────────────
// Two-step wizard:
//   Step 1 — pick a data source (cards, greyed out if no data in capture)
//   Step 2 — map fields + pick chart type + set title
export default function CustomChartBuilder({ onSave, onClose, initial }) {
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
