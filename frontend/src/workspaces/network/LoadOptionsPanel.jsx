/**
 * LoadOptionsPanel — shown after a pcap prescan completes.
 *
 * Displays capture summary (packets, duration, IP/pair counts) and lets the
 * user narrow the load via:
 *   • Time range      — dual range sliders over the capture window
 *   • Protocols       — checkboxes for L4 protocols found in the prescan
 *   • IP / subnet     — free-text, comma-separated IPs or CIDR notation
 *   • Port / range    — free-text, comma-separated ports or ranges
 *   • Top-K flows     — optional; keep only K busiest session pairs
 *
 * Props:
 *   data             — prescan response from POST /api/upload/prescan
 *   onLoad(filter)   — called when the user confirms; filter is the JSON body
 *                      for POST /api/upload/load
 *   onCancel()       — called when the user dismisses the panel
 */

import React, { useState, useMemo } from 'react';

// ── helpers ──────────────────────────────────────────────────────────────────

function fmtDuration(seconds) {
  if (!seconds || seconds <= 0) return '0s';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function fmtOffset(totalSec, frac) {
  const s = Math.round(totalSec * frac);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}`;
}

function fmtNum(n) {
  return n == null ? '—' : n.toLocaleString();
}

function estColor(n) {
  if (n < 200_000) return '#3fb950';
  if (n < 500_000) return '#d29922';
  return '#f85149';
}

// ── component ─────────────────────────────────────────────────────────────────

export default function LoadOptionsPanel({ data, onLoad, onCancel }) {
  const {
    filename = '',
    file_size_mb = 0,
    packet_count = 0,
    ts_first = null,
    ts_last  = null,
    duration_seconds = 0,
    node_count = 0,
    edge_count = 0,
    protocols: prescanProtos = {},
    top_ips = [],
  } = data || {};

  // ── time range ───────────────────────────────────────────────────
  const [startFrac, setStartFrac] = useState(0);
  const [endFrac,   setEndFrac]   = useState(1);
  const timeModified = startFrac > 0.0005 || endFrac < 0.9995;

  // ── protocols ────────────────────────────────────────────────────
  const protoList = useMemo(
    () => Object.entries(prescanProtos).sort((a, b) => b[1] - a[1]),
    [prescanProtos],
  );
  const [enabledProtos, setEnabledProtos] = useState(() => new Set(protoList.map(([k]) => k)));

  function toggleProto(name) {
    setEnabledProtos(prev => {
      const next = new Set(prev);
      next.has(name) ? next.delete(name) : next.add(name);
      return next;
    });
  }

  // ── IP filter ────────────────────────────────────────────────────
  const [ipText,    setIpText]    = useState('');
  const [ipExcText, setIpExcText] = useState('');

  // ── Port filter ──────────────────────────────────────────────────
  const [portText,    setPortText]    = useState('');
  const [portExcText, setPortExcText] = useState('');

  // ── Top-K ────────────────────────────────────────────────────────
  const [topKEnabled, setTopKEnabled] = useState(false);
  const [topKValue,   setTopKValue]   = useState(100);

  // ── Estimated counts (packets, edges, nodes) ─────────────────────
  const timeFrac = duration_seconds > 0 ? (endFrac - startFrac) : 1;
  const allProtosEnabled = protoList.length === 0 || enabledProtos.size === protoList.length;
  const protoFrac = allProtosEnabled
    ? 1
    : [...enabledProtos].reduce((acc, name) => acc + (prescanProtos[name] || 0), 0) / (packet_count || 1);

  const basePkts  = Math.round(packet_count * timeFrac * protoFrac);
  const baseEdges = Math.round(edge_count   * timeFrac * protoFrac);
  // nodes shrink slower than edges (hub nodes appear in many flows)
  const baseNodes = Math.round(node_count   * Math.sqrt(timeFrac * protoFrac));

  let estimated  = basePkts;
  let estEdges   = baseEdges;
  let estNodes   = baseNodes;

  if (topKEnabled && topKValue > 0) {
    // top-K caps flows exactly; packets estimated from avg flow size
    const avgPktsPerFlow = edge_count > 0 ? packet_count / edge_count : packet_count;
    estimated = Math.min(basePkts,  Math.round(topKValue * avgPktsPerFlow));
    estEdges  = Math.min(baseEdges, topKValue);
    estNodes  = Math.min(baseNodes, topKValue * 2);
  }

  const hasIpFilter   = ipText.trim()   || ipExcText.trim();
  const hasPortFilter = portText.trim() || portExcText.trim();

  // ── submit ───────────────────────────────────────────────────────
  function handleLoad() {
    const filter = {};
    if (timeModified && ts_first != null && ts_last != null) {
      filter.ts_start = ts_first + startFrac * duration_seconds;
      filter.ts_end   = ts_first + endFrac   * duration_seconds;
    }
    if (!allProtosEnabled) {
      filter.protocols = [...enabledProtos];
    }
    const ips = ipText.split(',').map(s => s.trim()).filter(Boolean);
    if (ips.length) filter.ip_whitelist = ips;

    const ipExc = ipExcText.split(',').map(s => s.trim()).filter(Boolean);
    if (ipExc.length) filter.ip_blacklist = ipExc;

    const ports = portText.split(',').map(s => s.trim()).filter(Boolean);
    if (ports.length) filter.port_whitelist = ports;

    const portExc = portExcText.split(',').map(s => s.trim()).filter(Boolean);
    if (portExc.length) filter.port_blacklist = portExc;

    if (topKEnabled && topKValue > 0) filter.top_k_flows = topKValue;

    onLoad(filter);
  }

  // ── styles ───────────────────────────────────────────────────────
  const card = {
    background: 'var(--bg)',
    border: '1.5px solid rgba(88,166,255,.25)',
    borderRadius: 16,
    padding: '28px 32px',
    width: 520,
    maxHeight: '90vh',
    overflowY: 'auto',
    boxShadow: '0 8px 32px rgba(0,0,0,.4)',
    fontFamily: 'var(--fn)',
    fontSize: 13,
    color: 'var(--txM)',
  };
  const label = { color: 'var(--txD)', fontSize: 11, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.06em' };
  const section = { marginBottom: 20 };
  const inputStyle = {
    width: '100%', boxSizing: 'border-box',
    background: '#0d1117', border: '1px solid var(--bd)', borderRadius: 6,
    color: 'var(--txM)', padding: '6px 10px', fontSize: 12, outline: 'none',
  };

  return (
    <div style={card}>
      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--txH)', marginBottom: 4 }}>
          Load Options
        </div>
        <div style={{ color: 'var(--txD)', fontSize: 12 }}>
          {filename} &nbsp;·&nbsp; {file_size_mb.toFixed(1)} MB
        </div>
      </div>

      {/* Summary strip */}
      <div style={{ ...section, display: 'flex', gap: 20, flexWrap: 'wrap', padding: '10px 14px', background: 'rgba(88,166,255,.05)', borderRadius: 8 }}>
        <Stat label="Packets"  value={fmtNum(packet_count)} />
        <Stat label="Duration" value={fmtDuration(duration_seconds)} />
        <Stat label="Unique IPs"    value={fmtNum(node_count)} />
        <Stat label="IP pairs" value={fmtNum(edge_count)} />
      </div>

      {/* Time range */}
      <div style={section}>
        <div style={label}>Time Range</div>
        {/* Visual bar */}
        <div style={{ position: 'relative', height: 16, borderRadius: 8, background: 'rgba(88,166,255,.08)', border: '1px solid rgba(88,166,255,.15)', marginBottom: 8 }}>
          <div style={{
            position: 'absolute', top: 0, bottom: 0,
            left: `${startFrac * 100}%`,
            width: `${(endFrac - startFrac) * 100}%`,
            background: 'rgba(88,166,255,.35)',
            borderRadius: 8,
            transition: 'all 0.05s',
          }} />
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <div style={{ flex: 1 }}>
            <div style={{ ...label, marginBottom: 3 }}>Start &nbsp; {fmtOffset(duration_seconds, startFrac)}</div>
            <input type="range" min={0} max={1000} value={Math.round(startFrac * 1000)}
              onChange={e => setStartFrac(Math.min(Number(e.target.value) / 1000, endFrac - 0.001))}
              style={{ width: '100%' }}
            />
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ ...label, marginBottom: 3 }}>End &nbsp; {fmtOffset(duration_seconds, endFrac)}</div>
            <input type="range" min={0} max={1000} value={Math.round(endFrac * 1000)}
              onChange={e => setEndFrac(Math.max(Number(e.target.value) / 1000, startFrac + 0.001))}
              style={{ width: '100%' }}
            />
          </div>
        </div>
      </div>

      {/* Protocol filter */}
      {protoList.length > 0 && (
        <div style={section}>
          <div style={{ ...label, display: 'flex', justifyContent: 'space-between' }}>
            <span>Protocols</span>
            <span
              style={{ cursor: 'pointer', color: 'var(--ac)', textTransform: 'none', letterSpacing: 0 }}
              onClick={() => setEnabledProtos(
                enabledProtos.size === protoList.length
                  ? new Set()
                  : new Set(protoList.map(([k]) => k))
              )}
            >
              {enabledProtos.size === protoList.length ? 'Deselect all' : 'Select all'}
            </span>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {protoList.map(([name, count]) => (
              <label key={name} style={{ display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={enabledProtos.has(name)}
                  onChange={() => toggleProto(name)}
                />
                <span style={{ color: enabledProtos.has(name) ? 'var(--txM)' : 'var(--txD)' }}>
                  {name} <span style={{ color: 'var(--txD)' }}>({fmtNum(count)})</span>
                </span>
              </label>
            ))}
          </div>
        </div>
      )}

      {/* IP filter */}
      <div style={section}>
        <div style={label}>IP / Subnet — Keep <span style={{ textTransform: 'none', letterSpacing: 0 }}>(comma-separated; empty = all)</span></div>
        <input
          style={inputStyle}
          placeholder="e.g. 192.168.1.0/24, 10.0.0.1, 172.16.0.0/12"
          value={ipText}
          onChange={e => setIpText(e.target.value)}
        />
        {top_ips.length > 0 && (
          <div style={{ marginTop: 6, display: 'flex', flexWrap: 'wrap', gap: 5 }}>
            {top_ips.slice(0, 8).map(({ ip }) => (
              <span
                key={ip}
                onClick={() => setIpText(t => t ? `${t}, ${ip}` : ip)}
                style={{
                  fontSize: 11, padding: '2px 8px', borderRadius: 4,
                  background: 'rgba(88,166,255,.1)', border: '1px solid rgba(88,166,255,.2)',
                  cursor: 'pointer', color: 'var(--ac)',
                }}
              >
                {ip}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* IP exclusion */}
      <div style={section}>
        <div style={label}>IP / Subnet — Exclude <span style={{ textTransform: 'none', letterSpacing: 0 }}>(comma-separated)</span></div>
        <input
          style={{ ...inputStyle, borderColor: 'rgba(248,81,73,.3)' }}
          placeholder="e.g. 10.0.0.254, 239.0.0.0/8"
          value={ipExcText}
          onChange={e => setIpExcText(e.target.value)}
        />
        {top_ips.length > 0 && ipExcText === '' && (
          <div style={{ marginTop: 6, display: 'flex', flexWrap: 'wrap', gap: 5 }}>
            {top_ips.slice(0, 8).map(({ ip }) => (
              <span
                key={ip}
                onClick={() => setIpExcText(t => t ? `${t}, ${ip}` : ip)}
                style={{
                  fontSize: 11, padding: '2px 8px', borderRadius: 4,
                  background: 'rgba(248,81,73,.08)', border: '1px solid rgba(248,81,73,.25)',
                  cursor: 'pointer', color: '#f85149',
                }}
              >
                {ip}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Port filter */}
      <div style={section}>
        <div style={label}>Port — Keep <span style={{ textTransform: 'none', letterSpacing: 0 }}>(comma-separated ports or ranges)</span></div>
        <input
          style={inputStyle}
          placeholder="e.g. 80, 443, 8000-9000, 53"
          value={portText}
          onChange={e => setPortText(e.target.value)}
        />
      </div>

      {/* Port exclusion */}
      <div style={section}>
        <div style={label}>Port — Exclude <span style={{ textTransform: 'none', letterSpacing: 0 }}>(comma-separated ports or ranges)</span></div>
        <input
          style={{ ...inputStyle, borderColor: 'rgba(248,81,73,.3)' }}
          placeholder="e.g. 6881-6889, 4444, 9001"
          value={portExcText}
          onChange={e => setPortExcText(e.target.value)}
        />
      </div>

      {/* Top-K flows */}
      <div style={{ ...section, display: 'flex', alignItems: 'center', gap: 10 }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
          <input type="checkbox" checked={topKEnabled} onChange={e => setTopKEnabled(e.target.checked)} />
          <span>Top-K flows only</span>
        </label>
        {topKEnabled && (
          <input
            type="number" min={1} max={100000} value={topKValue}
            onChange={e => setTopKValue(Math.max(1, Number(e.target.value) || 1))}
            style={{ ...inputStyle, width: 90 }}
          />
        )}
      </div>

      {/* Estimate */}
      <div style={{ ...section, padding: '10px 14px', borderRadius: 8, background: 'rgba(0,0,0,.15)' }}>
        <div style={{ fontSize: 10, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
          After filters (estimated)
        </div>
        <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap', alignItems: 'baseline' }}>
          <span>
            <span style={{ color: 'var(--txD)', fontSize: 11 }}>Packets </span>
            <span style={{ fontWeight: 600, fontSize: 14, color: estColor(estimated) }}>~{fmtNum(estimated)}</span>
          </span>
          <span>
            <span style={{ color: 'var(--txD)', fontSize: 11 }}>Flows </span>
            <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--txH)' }}>~{fmtNum(estEdges)}</span>
          </span>
          <span>
            <span style={{ color: 'var(--txD)', fontSize: 11 }}>IPs </span>
            <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--txH)' }}>~{fmtNum(estNodes)}</span>
          </span>
        </div>
        {estimated > 500_000 && (
          <div style={{ marginTop: 6, fontSize: 11, color: '#d29922' }}>Large — consider narrowing the time range</div>
        )}
        {(hasIpFilter || hasPortFilter) && (
          <div style={{ marginTop: 4, fontSize: 11, color: 'var(--txD)' }}>
            IP/port filter active — counts are approximate
          </div>
        )}
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <button
          className="btn"
          onClick={handleLoad}
          disabled={enabledProtos.size === 0}
          style={{ flex: 1, padding: '8px 0', background: 'var(--ac)', color: '#000', fontWeight: 600, fontSize: 13 }}
        >
          Load Capture
        </button>
        <span
          onClick={onCancel}
          style={{ cursor: 'pointer', color: 'var(--txD)', fontSize: 12 }}
        >
          Cancel
        </span>
      </div>
    </div>
  );
}

function Stat({ label, value }) {
  return (
    <div style={{ textAlign: 'center', minWidth: 70 }}>
      <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--txH)' }}>{value}</div>
      <div style={{ fontSize: 10, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</div>
    </div>
  );
}
