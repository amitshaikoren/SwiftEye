import React, { useState } from 'react';
import { fB } from '../utils';
import { NODE_LEGENDS, EDGE_LEGENDS } from './graph/graphLegendData';

// ── Toggle switch ─────────────────────────────────────────────────────────────
function Toggle({ checked, onChange, title }) {
  return (
    <div title={title} onClick={() => onChange(!checked)} style={{
      position: 'relative', width: 32, height: 18, flexShrink: 0, cursor: 'pointer',
    }}>
      <div style={{
        position: 'absolute', inset: 0, borderRadius: 9,
        background: checked ? 'var(--ac)' : 'var(--bgH)',
        border: '1px solid ' + (checked ? 'var(--ac)' : 'var(--bd)'),
        transition: 'all .15s',
      }} />
      <div style={{
        position: 'absolute', top: 2, left: checked ? 16 : 2,
        width: 12, height: 12, borderRadius: '50%',
        background: checked ? '#fff' : 'var(--txD)',
        transition: 'all .15s',
      }} />
    </div>
  );
}

// ── Segmented control ─────────────────────────────────────────────────────────
function Seg({ options, value, onChange }) {
  return (
    <div style={{
      display: 'flex', background: 'var(--bgC)', border: '1px solid var(--bd)',
      borderRadius: 6, padding: 2, gap: 2,
    }}>
      {options.map(({ id, label }) => (
        <button key={id} onClick={() => onChange(id)} style={{
          flex: 1, fontSize: 10, padding: '4px 0',
          background: value === id ? 'var(--bgH)' : 'none',
          border: 'none', borderRadius: 4,
          color: value === id ? 'var(--tx)' : 'var(--txM)',
          fontWeight: value === id ? 600 : 400,
          cursor: 'pointer', fontFamily: 'var(--fn)',
          transition: 'all .12s',
        }}>
          {label}
        </button>
      ))}
    </div>
  );
}

// ── Collapsible section ───────────────────────────────────────────────────────
function Section({ title, children, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{ padding: '0 14px' }}>
      <div onClick={() => setOpen(o => !o)} style={{
        display: 'flex', alignItems: 'center', gap: 6,
        padding: '10px 0 7px',
        fontSize: 9, fontWeight: 600, letterSpacing: '.09em', textTransform: 'uppercase',
        color: 'var(--txD)', fontFamily: 'var(--fn)',
        borderBottom: '1px solid var(--bgH)', marginBottom: open ? 10 : 0,
        cursor: 'pointer', userSelect: 'none',
      }}>
        {title}
        <span style={{ marginLeft: 'auto', fontSize: 9, transition: 'transform .15s', transform: open ? '' : 'rotate(-90deg)' }}>▾</span>
      </div>
      {open && children}
    </div>
  );
}

// ── Row layout ────────────────────────────────────────────────────────────────
function Row({ label, hint, children }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '5px 0', gap: 8 }}>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 12, color: 'var(--tx)', lineHeight: 1.3 }}>{label}</div>
        {hint && <div style={{ fontSize: 10, color: 'var(--txD)', fontFamily: 'var(--fn)', marginTop: 1 }}>{hint}</div>}
      </div>
      {children}
    </div>
  );
}

// ── Color mode card grid ──────────────────────────────────────────────────────
const NODE_MODES = [
  { id: 'address',  icon: '🌐', name: 'Address',  hint: 'Private vs external' },
  { id: 'os',       icon: '💻', name: 'OS',        hint: 'Detected OS family' },
  { id: 'protocol', icon: '📡', name: 'Protocol',  hint: 'Dominant protocol' },
  { id: 'volume',   icon: '🔥', name: 'Volume',    hint: 'Bytes transferred' },
  { id: 'custom',   icon: '🎨', name: 'Custom',    hint: 'Your own IP rules' },
];

const EDGE_MODES = [
  { id: 'protocol', icon: '📡', name: 'Protocol', hint: 'Per-protocol color' },
  { id: 'volume',   icon: '🔥', name: 'Volume',   hint: 'Bytes transferred' },
  { id: 'sessions', icon: '🔗', name: 'Sessions', hint: 'Session count' },
  { id: 'custom',   icon: '🎨', name: 'Custom',   hint: 'Your own rules' },
];

const LBL_STEPS = [0, 1024, 10240, 102400, 1048576, 10485760];
const LBL_HINTS = [
  'Show all node labels',
  'Hide labels on very low-traffic nodes',
  'Only label nodes with ≥ 10 KB traffic',
  'Only label nodes with ≥ 100 KB traffic',
  'Only label major hubs',
  'Only label the busiest nodes',
];

// ── Custom rules editor ───────────────────────────────────────────────────────
function CustomRules({ rules, onChange, placeholder }) {
  function addRule() {
    onChange([...rules, { color: '#58a6ff', text: '' }]);
  }
  function removeRule(i) {
    const next = [...rules]; next.splice(i, 1); onChange(next);
  }
  function updateColor(i, color) {
    const next = [...rules]; next[i] = { ...next[i], color }; onChange(next);
  }
  function updateText(i, text) {
    const next = [...rules]; next[i] = { ...next[i], text }; onChange(next);
  }

  return (
    <div style={{ marginTop: 8 }}>
      {rules.length === 0 ? (
        <div style={{
          fontSize: 10, color: 'var(--txD)', fontFamily: 'var(--fn)',
          padding: '8px 10px', background: 'var(--bgC)',
          border: '1px dashed var(--bd)', borderRadius: 6,
          textAlign: 'center', lineHeight: 1.6,
        }}>
          No rules yet.<br />Add a rule to color {placeholder} by IP or keyword.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
          {rules.map((r, i) => (
            <div key={i} style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: 'var(--bgC)', border: '1px solid var(--bd)',
              borderRadius: 6, padding: '5px 8px',
            }}>
              {/* Color swatch + picker */}
              <div style={{ position: 'relative', width: 16, height: 16, flexShrink: 0 }}>
                <div style={{
                  width: 16, height: 16, borderRadius: 4,
                  background: r.color, border: '1.5px solid rgba(255,255,255,.15)',
                  cursor: 'pointer',
                }} />
                <input type="color" value={r.color} onChange={e => updateColor(i, e.target.value)}
                  style={{ position: 'absolute', inset: 0, opacity: 0, cursor: 'pointer', width: '100%', height: '100%', border: 'none', padding: 0 }} />
              </div>
              <input
                type="text" value={r.text}
                onChange={e => updateText(i, e.target.value)}
                placeholder={placeholder}
                style={{
                  flex: 1, fontSize: 10, fontFamily: 'var(--fn)', color: 'var(--tx)',
                  background: 'none', border: 'none', outline: 'none', minWidth: 0,
                }}
              />
              <button onClick={() => removeRule(i)} style={{
                background: 'none', border: 'none', color: 'var(--txD)',
                cursor: 'pointer', fontSize: 13, lineHeight: 1, padding: '0 2px', flexShrink: 0,
              }}
                onMouseEnter={e => e.currentTarget.style.color = 'var(--acR)'}
                onMouseLeave={e => e.currentTarget.style.color = 'var(--txD)'}
              >✕</button>
            </div>
          ))}
        </div>
      )}
      <button onClick={addRule} style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 5,
        width: '100%', padding: '6px 0', fontSize: 11, color: 'var(--ac)',
        background: 'none', border: '1.5px dashed var(--bdL)', borderRadius: 6,
        cursor: 'pointer', fontFamily: 'var(--fd)', marginTop: 6, transition: 'all .15s',
      }}
        onMouseEnter={e => { e.currentTarget.style.background = 'rgba(88,166,255,.06)'; e.currentTarget.style.borderColor = 'var(--ac)'; }}
        onMouseLeave={e => { e.currentTarget.style.background = 'none'; e.currentTarget.style.borderColor = 'var(--bdL)'; }}
      >
        + Add rule
      </button>
    </div>
  );
}

// ── Color mode section (shared for node/edge) ─────────────────────────────────
function ColorBySection({ modes, legends, selected, onSelect, rules, onRulesChange, placeholder, hasOsData }) {
  const legend = legends[selected];
  return (
    <div>
      <div style={{ fontSize: 11, color: 'var(--tx)', marginBottom: 2 }}>Color by</div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginTop: 8 }}>
        {modes.map(m => {
          const disabled = m.id === 'os' && !hasOsData;
          const isSel = selected === m.id;
          return (
            <div key={m.id}
              onClick={() => !disabled && onSelect(m.id)}
              title={disabled ? 'No OS data in this capture' : undefined}
              style={{
                background: isSel ? 'rgba(88,166,255,.07)' : 'var(--bgC)',
                border: '1.5px solid ' + (isSel ? 'var(--ac)' : 'var(--bd)'),
                borderRadius: 8, padding: '8px 10px', cursor: disabled ? 'not-allowed' : 'pointer',
                opacity: disabled ? 0.38 : 1,
                display: 'flex', flexDirection: 'column', gap: 3,
                transition: 'all .15s',
              }}
            >
              <div style={{ fontSize: 15, lineHeight: 1 }}>{m.icon}</div>
              <div style={{ fontSize: 11, fontWeight: 600, color: isSel ? 'var(--ac)' : 'var(--tx)' }}>{m.name}</div>
              <div style={{ fontSize: 9, color: 'var(--txD)', lineHeight: 1.35 }}>{m.hint}</div>
            </div>
          );
        })}
      </div>

      {selected === 'custom' ? (
        <CustomRules rules={rules} onChange={onRulesChange} placeholder={placeholder} />
      ) : legend ? (
        <div style={{
          marginTop: 10, padding: '8px 10px',
          background: 'var(--bgC)', border: '1px solid var(--bd)', borderRadius: 6,
          display: 'flex', flexDirection: 'column', gap: 4,
        }}>
          {legend.map((item, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 10, color: 'var(--txM)', fontFamily: 'var(--fn)' }}>
              {item.dot ? (
                <div style={{
                  width: 10, height: 10, borderRadius: '50%', flexShrink: 0,
                  background: item.fill, border: '1.5px solid ' + item.stroke,
                }} />
              ) : (
                <div style={{ width: 22, height: 3, borderRadius: 2, background: item.fill, flexShrink: 0 }} />
              )}
              {item.label}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────────
export default function GraphOptionsPanel({
  onClose,
  // Layout
  layoutMode = 'force', setLayoutMode,
  // Node display
  nodeColorMode, setNodeColorMode,
  nodeColorRules, setNodeColorRules,
  graphWeightMode, setGraphWeightMode,
  labelThreshold, setLabelThreshold,
  // Edge display
  edgeColorMode, setEdgeColorMode,
  edgeColorRules, setEdgeColorRules,
  edgeSizeMode, setEdgeSizeMode,
  showEdgeDirection, setShowEdgeDirection,
  // Data
  subnetG, setSubnetG, toggleSubnetG,
  subnetPrefix, setSubnetPrefix,
  mergeByMac, setMergeByMac,
  includeIPv6, setIncludeIPv6,
  showHostnames, setShowHostnames,
  excludeBroadcasts, setExcludeBroadcasts,
  // Clustering
  clusterAlgo, setClusterAlgo,
  clusterResolution, setClusterResolution,
  // Data availability
  visibleNodes,
}) {
  const [neMode, setNeMode] = useState('node'); // 'node' | 'edge'

  const hasOsData = (visibleNodes || []).some(n => n.os_guess);

  // ── Label threshold step index ─────────────────────────────────────
  const lblIdx = LBL_STEPS.reduce((best, v, i) =>
    Math.abs(v - labelThreshold) < Math.abs(LBL_STEPS[best] - labelThreshold) ? i : best, 0);

  const clusterHints = {
    '': 'No clustering applied',
    louvain: 'Groups densely connected communities',
    kcore: 'Reveals the dense backbone of the graph',
    hub_spoke: 'Collapses leaf nodes around hubs',
    shared_neighbor: 'Groups nodes with identical peers',
  };

  return (
    <div style={{
      width: '100%', height: '100%',
      background: 'var(--bgP)',
      display: 'flex', flexDirection: 'column',
      overflow: 'hidden',
    }}>

        {/* Header */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '13px 14px 12px', borderBottom: '1px solid var(--bd)', flexShrink: 0,
        }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--tx)', display: 'flex', alignItems: 'center', gap: 7 }}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" style={{ opacity: .5 }}>
              <circle cx="12" cy="12" r="3"/>
              <path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/>
            </svg>
            Graph Options
          </div>
          <button onClick={onClose} style={{
            width: 22, height: 22, background: 'none', border: 'none',
            color: 'var(--txM)', cursor: 'pointer', display: 'flex',
            alignItems: 'center', justifyContent: 'center',
            borderRadius: 4, fontSize: 15, transition: 'all .12s',
          }}
            onMouseEnter={e => { e.currentTarget.style.background = 'var(--bgH)'; e.currentTarget.style.color = 'var(--tx)'; }}
            onMouseLeave={e => { e.currentTarget.style.background = 'none'; e.currentTarget.style.color = 'var(--txM)'; }}
          >✕</button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '6px 0 20px' }}>

          {/* ── LAYOUT ──────────────────────────────────────────── */}
          <Section title="Layout">
            <div style={{
              display: 'flex', background: 'var(--bgC)', border: '1px solid var(--bd)',
              borderRadius: 7, padding: 2, gap: 2,
            }}>
              {[
                { id: 'force',    label: 'Force',    title: 'D3 force simulation — organic, cluster-aware' },
                { id: 'circular', label: 'Circular', title: 'Nodes arranged on concentric rings by degree (≤60 nodes)' },
              ].map(({ id, label, title }) => (
                <button key={id} onClick={() => setLayoutMode(id)} title={title} style={{
                  flex: 1, fontSize: 11, padding: '5px 0',
                  background: layoutMode === id ? 'var(--bgH)' : 'none',
                  border: 'none', borderRadius: 5,
                  color: layoutMode === id ? 'var(--tx)' : 'var(--txM)',
                  fontWeight: layoutMode === id ? 600 : 400,
                  cursor: 'pointer', fontFamily: 'var(--fd)',
                  transition: 'all .12s',
                }}>
                  {label}
                </button>
              ))}
            </div>
            {layoutMode === 'circular' && (
              <div style={{ fontSize: 10, color: 'var(--txM)', marginTop: 7, lineHeight: 1.4 }}>
                Nodes arranged by degree on concentric rings. Falls back to Force for graphs over 60 nodes.
              </div>
            )}
          </Section>

          {/* ── DISPLAY ─────────────────────────────────────────── */}
          <Section title="Display">
            {/* Node / Edge flip */}
            <div style={{
              display: 'flex', background: 'var(--bgC)', border: '1px solid var(--bd)',
              borderRadius: 7, padding: 2, gap: 2, marginBottom: 12,
            }}>
              {[
                { id: 'node', label: 'Nodes', icon: '●' },
                { id: 'edge', label: 'Edges', icon: '—' },
              ].map(({ id, label, icon }) => (
                <button key={id} onClick={() => setNeMode(id)} style={{
                  flex: 1, fontSize: 11, padding: '5px 0',
                  background: neMode === id ? 'var(--bgH)' : 'none',
                  border: 'none', borderRadius: 5,
                  color: neMode === id ? 'var(--tx)' : 'var(--txM)',
                  fontWeight: neMode === id ? 600 : 400,
                  cursor: 'pointer', fontFamily: 'var(--fd)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 5,
                  transition: 'all .12s',
                }}>
                  <span style={{ fontSize: neMode === id ? 12 : 10, opacity: neMode === id ? 1 : .6 }}>{icon}</span>
                  {label}
                </button>
              ))}
            </div>

            {neMode === 'node' ? (
              <>
                {/* Node size */}
                <div style={{ marginBottom: 10 }}>
                  <div style={{ fontSize: 11, color: 'var(--tx)', marginBottom: 5 }}>Size by</div>
                  <Seg
                    options={[{ id: 'bytes', label: 'Bytes' }, { id: 'packets', label: 'Packets' }]}
                    value={graphWeightMode}
                    onChange={setGraphWeightMode}
                  />
                  <div style={{ fontSize: 10, color: 'var(--txD)', fontFamily: 'var(--fn)', marginTop: 4 }}>
                    Node radius scales logarithmically with the selected metric.
                  </div>
                </div>

                {/* Node color */}
                <ColorBySection
                  modes={NODE_MODES}
                  legends={NODE_LEGENDS}
                  selected={nodeColorMode}
                  onSelect={setNodeColorMode}
                  rules={nodeColorRules}
                  onRulesChange={setNodeColorRules}
                  placeholder="IP, CIDR, or hostname…"
                  hasOsData={hasOsData}
                />

                {/* Label threshold */}
                <div style={{ marginTop: 12, paddingBottom: 4 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                    <span style={{ fontSize: 11, color: 'var(--tx)' }}>Label threshold</span>
                    <span style={{ fontSize: 10, fontFamily: 'var(--fn)', color: 'var(--txM)' }}>
                      {labelThreshold === 0 ? 'All labels' : `≥ ${fB(labelThreshold)}`}
                    </span>
                  </div>
                  <input type="range" min={0} max={LBL_STEPS.length - 1} step={1} value={lblIdx}
                    onChange={e => setLabelThreshold(LBL_STEPS[+e.target.value])}
                    style={{ width: '100%', accentColor: 'var(--ac)' }}
                  />
                  <div style={{ fontSize: 10, color: 'var(--txD)', fontFamily: 'var(--fn)', marginTop: 3 }}>
                    {LBL_HINTS[lblIdx]}
                  </div>
                </div>
              </>
            ) : (
              <>
                {/* Edge thickness */}
                <div style={{ marginBottom: 10 }}>
                  <div style={{ fontSize: 11, color: 'var(--tx)', marginBottom: 5 }}>Thickness by</div>
                  <Seg
                    options={[
                      { id: 'bytes',    label: 'Bytes' },
                      { id: 'packets',  label: 'Packets' },
                      { id: 'sessions', label: 'Sessions' },
                    ]}
                    value={edgeSizeMode}
                    onChange={setEdgeSizeMode}
                  />
                  <div style={{ fontSize: 10, color: 'var(--txD)', fontFamily: 'var(--fn)', marginTop: 4 }}>
                    Edge stroke width scales with the selected metric.
                  </div>
                </div>

                {/* Edge color */}
                <ColorBySection
                  modes={EDGE_MODES}
                  legends={EDGE_LEGENDS}
                  selected={edgeColorMode}
                  onSelect={setEdgeColorMode}
                  rules={edgeColorRules}
                  onRulesChange={setEdgeColorRules}
                  placeholder="Protocol name or keyword…"
                  hasOsData={true}
                />

                {/* Edge direction */}
                <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: 11, color: 'var(--tx)' }}>Show direction</span>
                  <button
                    onClick={() => setShowEdgeDirection(v => !v)}
                    style={{
                      background: showEdgeDirection ? 'var(--ac)' : 'var(--bgH)',
                      border: '1px solid var(--bdL)',
                      borderRadius: 4, padding: '2px 10px', fontSize: 11,
                      color: showEdgeDirection ? '#fff' : 'var(--txM)', cursor: 'pointer',
                    }}
                  >{showEdgeDirection ? 'On' : 'Off'}</button>
                </div>
                <div style={{ fontSize: 10, color: 'var(--txD)', fontFamily: 'var(--fn)', marginTop: 3 }}>
                  Draw arrowheads on edges (src → dst).
                </div>
              </>
            )}
          </Section>

          <div style={{ height: 1, background: 'var(--bgH)', margin: '6px 14px 10px' }} />

          {/* ── DATA ────────────────────────────────────────────── */}
          <Section title="Data">
            {/* Subnet grouping */}
            <Row label="Subnet grouping" hint="Group IPs by prefix">
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 10, color: 'var(--txD)', fontFamily: 'var(--fn)' }}>/</span>
                <input
                  type="number" min={8} max={32} value={subnetPrefix}
                  onChange={e => setSubnetPrefix(Math.max(8, Math.min(32, +e.target.value)))}
                  style={{
                    width: 44, fontSize: 11, padding: '2px 4px', textAlign: 'center',
                    background: 'var(--bgC)', border: '1px solid var(--bd)', borderRadius: 4,
                    color: subnetG ? 'var(--tx)' : 'var(--txD)', fontFamily: 'var(--fn)', outline: 'none',
                    opacity: subnetG ? 1 : .4, transition: 'opacity .15s', flexShrink: 0,
                  }}
                />
                <Toggle checked={subnetG} onChange={v => toggleSubnetG ? toggleSubnetG() : setSubnetG(v)} title="Toggle subnet grouping" />
              </div>
            </Row>

            {[
              [mergeByMac, setMergeByMac, 'Merge by MAC', 'Collapse dual-stack into one node', 'Merge IPs sharing a MAC address into one node'],
              [includeIPv6, setIncludeIPv6, 'Show IPv6', 'Include fe80::, ff02:: nodes', 'Toggle off to hide IPv6 nodes'],
              [showHostnames, setShowHostnames, 'Show hostnames', 'DNS names as node labels', 'Show DNS-resolved hostnames instead of raw IPs'],
              [excludeBroadcasts, setExcludeBroadcasts, 'Hide broadcasts', 'Drop 255.255.255.255, 224.0.0.0/4', 'Hide broadcast and multicast addresses'],
            ].map(([val, setter, label, hint, tip]) => (
              <Row key={label} label={label} hint={hint}>
                <Toggle checked={val} onChange={setter} title={tip} />
              </Row>
            ))}
          </Section>

          <div style={{ height: 1, background: 'var(--bgH)', margin: '6px 14px 10px' }} />

          {/* ── CLUSTERING ──────────────────────────────────────── */}
          <Section title="Clustering">
            <div style={{ fontSize: 11, color: 'var(--tx)', marginBottom: 2 }}>Algorithm</div>
            <select
              value={clusterAlgo}
              onChange={e => setClusterAlgo(e.target.value)}
              style={{
                width: '100%', fontSize: 11, padding: '5px 24px 5px 8px',
                background: 'var(--bgC)', color: 'var(--tx)',
                border: '1px solid var(--bd)', borderRadius: 6,
                fontFamily: 'var(--fn)', outline: 'none', cursor: 'pointer',
                appearance: 'none',
                backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%238b949e' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E")`,
                backgroundRepeat: 'no-repeat', backgroundPosition: 'right 8px center',
                marginTop: 5,
              }}
            >
              <option value="">None</option>
              <option value="louvain">Louvain — communities</option>
              <option value="kcore">K-core — dense backbone</option>
              <option value="hub_spoke">Hub &amp; spoke — stars</option>
              <option value="shared_neighbor">Shared neighbors</option>
            </select>
            <div style={{ fontSize: 10, color: 'var(--txD)', fontFamily: 'var(--fn)', marginTop: 4 }}>
              {clusterHints[clusterAlgo] || ''}
            </div>

            {clusterAlgo === 'louvain' && (
              <div style={{ marginTop: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                  <span style={{ fontSize: 11, color: 'var(--tx)' }}>Resolution</span>
                  <span style={{ fontSize: 10, fontFamily: 'var(--fn)', color: 'var(--txM)' }}>{clusterResolution.toFixed(1)}</span>
                </div>
                <input type="range" min={0.1} max={3.0} step={0.1} value={clusterResolution}
                  onChange={e => setClusterResolution(parseFloat(e.target.value))}
                  style={{ width: '100%', accentColor: 'var(--ac)' }}
                />
                <div style={{ fontSize: 10, color: 'var(--txD)', fontFamily: 'var(--fn)', marginTop: 3 }}>
                  {clusterResolution < 0.8 ? 'Few large communities' : clusterResolution > 1.5 ? 'Many small communities' : 'Balanced'}
                </div>
              </div>
            )}
          </Section>

        </div>
    </div>
  );
}
