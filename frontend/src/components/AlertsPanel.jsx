import React, { useState, useMemo } from 'react';

const SEV_COLORS = {
  high:   { color: '#f85149', bg: 'rgba(248,81,73,0.10)', bd: 'rgba(248,81,73,0.28)' },
  medium: { color: '#d29922', bg: 'rgba(210,153,34,0.10)', bd: 'rgba(210,153,34,0.28)' },
  low:    { color: '#58a6ff', bg: 'rgba(88,166,255,0.08)', bd: 'rgba(88,166,255,0.22)' },
  info:   { color: '#484f58', bg: 'rgba(72,79,88,0.18)',   bd: 'rgba(72,79,88,0.40)' },
};

const SEV_ORDER = ['high', 'medium', 'low', 'info'];

function SevBadge({ severity }) {
  const c = SEV_COLORS[severity] || SEV_COLORS.info;
  return (
    <span style={{
      padding: '2px 7px', borderRadius: 3, flexShrink: 0,
      fontSize: 9, fontWeight: 700, letterSpacing: '.08em', textTransform: 'uppercase',
      background: c.bg, color: c.color, border: `1px solid ${c.bd}`, marginTop: 1,
    }}>{severity}</span>
  );
}

function AlertCard({ alert, expanded, onToggle, onShowInGraph }) {
  const c = SEV_COLORS[alert.severity] || SEV_COLORS.info;
  const ts = alert.timestamp ? new Date(alert.timestamp * 1000).toLocaleTimeString() : '';

  return (
    <div
      style={{
        background: 'var(--bgC)', border: '1px solid var(--bd)', borderRadius: 'var(--r)',
        overflow: 'hidden', cursor: 'pointer', transition: 'border-color .13s',
        borderLeft: `3px solid ${c.color}`, flexShrink: 0,
      }}
      onClick={onToggle}
    >
      {/* Top row — always visible */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '10px 12px 8px' }}>
        <SevBadge severity={alert.severity} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--tx)', marginBottom: 2 }}>{alert.title}</div>
          <div style={{ fontSize: 11, color: 'var(--txM)', lineHeight: 1.4 }}>{alert.subtitle}</div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4, flexShrink: 0 }}>
          {ts && <span style={{ fontSize: 9, color: 'var(--txD)', fontFamily: 'var(--fn)' }}>{ts}</span>}
          <button
            onClick={e => { e.stopPropagation(); onShowInGraph(alert); }}
            style={{
              fontSize: 9, padding: '2px 8px', borderRadius: 3, cursor: 'pointer',
              background: 'rgba(88,166,255,.08)', border: '1px solid rgba(88,166,255,.22)',
              color: 'var(--ac)', fontFamily: 'var(--fn)', whiteSpace: 'nowrap',
            }}
          >Show in graph</button>
        </div>
      </div>

      {/* IP tags + detector */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0 12px 8px', flexWrap: 'wrap' }}>
        {alert.src_ip && (
          <span style={{
            fontSize: 10, padding: '1px 6px', borderRadius: 3,
            background: 'rgba(63,185,80,.08)', border: '1px solid rgba(63,185,80,.22)',
            color: '#3fb950', fontFamily: 'var(--fn)',
          }}>{alert.src_ip}</span>
        )}
        {alert.dst_ip && (
          <span style={{
            fontSize: 10, padding: '1px 6px', borderRadius: 3,
            background: 'rgba(188,140,255,.08)', border: '1px solid rgba(188,140,255,.22)',
            color: '#bc8cff', fontFamily: 'var(--fn)',
          }}>{alert.dst_ip}</span>
        )}
        <span style={{ fontSize: 9, color: 'var(--txD)', marginLeft: 'auto', fontFamily: 'var(--fn)' }}>
          {alert.detector}
        </span>
      </div>

      {/* Evidence rows — expanded */}
      {expanded && alert.evidence && alert.evidence.length > 0 && (
        <div style={{ borderTop: '1px solid var(--bd)', padding: '8px 12px', background: 'var(--bgP)' }}>
          {alert.evidence.map((ev, i) => (
            <div key={i} style={{
              display: 'flex', alignItems: 'baseline', gap: 8, padding: '3px 0',
              fontSize: 11, borderBottom: i < alert.evidence.length - 1 ? '1px solid var(--bd)' : 'none',
            }}>
              <span style={{ color: 'var(--txD)', minWidth: 120, flexShrink: 0, fontWeight: 500 }}>{ev.key}</span>
              <span style={{ color: 'var(--tx)', fontFamily: 'var(--fn)', wordBreak: 'break-all' }}>{ev.value}</span>
              {ev.note && <span style={{ color: 'var(--txD)', fontSize: 10, marginLeft: 'auto', flexShrink: 0 }}>{ev.note}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function AlertsPanel({ alerts = [], summary = {}, onShowInGraph }) {
  const [sevFilter, setSevFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState('severity');
  const [expandedIds, setExpandedIds] = useState(new Set());

  const toggleExpand = (id) => {
    setExpandedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  // Filter
  const filtered = useMemo(() => {
    let list = alerts;
    if (sevFilter !== 'all') {
      list = list.filter(a => a.severity === sevFilter);
    }
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter(a => {
        if (a.src_ip && a.src_ip.toLowerCase().includes(q)) return true;
        if (a.dst_ip && a.dst_ip.toLowerCase().includes(q)) return true;
        if (a.detector && a.detector.toLowerCase().includes(q)) return true;
        if (a.title && a.title.toLowerCase().includes(q)) return true;
        if (a.subtitle && a.subtitle.toLowerCase().includes(q)) return true;
        // Search evidence values
        if (a.evidence) {
          for (const ev of a.evidence) {
            if (ev.value && ev.value.toLowerCase().includes(q)) return true;
            if (ev.key && ev.key.toLowerCase().includes(q)) return true;
          }
        }
        return false;
      });
    }
    return list;
  }, [alerts, sevFilter, search]);

  // Sort
  const sorted = useMemo(() => {
    const list = [...filtered];
    const sevOrd = { high: 0, medium: 1, low: 2, info: 3 };
    if (sortBy === 'severity') {
      list.sort((a, b) => (sevOrd[a.severity] ?? 9) - (sevOrd[b.severity] ?? 9) || (a.timestamp || 0) - (b.timestamp || 0));
    } else if (sortBy === 'time') {
      list.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
    } else if (sortBy === 'detector') {
      list.sort((a, b) => (a.detector || '').localeCompare(b.detector || '') || (sevOrd[a.severity] ?? 9) - (sevOrd[b.severity] ?? 9));
    }
    return list;
  }, [filtered, sortBy]);

  // Group by severity for section dividers (only in severity sort mode)
  const groups = useMemo(() => {
    if (sortBy !== 'severity') return null;
    const g = {};
    for (const a of sorted) {
      if (!g[a.severity]) g[a.severity] = [];
      g[a.severity].push(a);
    }
    return g;
  }, [sorted, sortBy]);

  const pills = [
    { key: 'all', label: 'All', count: alerts.length },
    { key: 'high', label: 'High', count: summary.high || 0 },
    { key: 'medium', label: 'Medium', count: summary.medium || 0 },
    { key: 'low', label: 'Low', count: summary.low || 0 },
    { key: 'info', label: 'Info', count: summary.info || 0 },
  ];

  const renderCard = (a) => (
    <AlertCard
      key={a.id}
      alert={a}
      expanded={expandedIds.has(a.id)}
      onToggle={() => toggleExpand(a.id)}
      onShowInGraph={onShowInGraph}
    />
  );

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Panel header */}
      <div style={{ flexShrink: 0, padding: '14px 18px 0' }}>
        {/* Title row */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
          <span style={{ fontFamily: 'var(--fd)', fontSize: 16, fontWeight: 600, color: 'var(--tx)' }}>Alerts</span>
          {(summary.total || 0) > 0 && (
            <span style={{
              padding: '2px 9px', borderRadius: 10,
              background: SEV_COLORS.high.bg, border: `1px solid ${SEV_COLORS.high.bd}`,
              color: SEV_COLORS.high.color, fontSize: 10, fontWeight: 700,
            }}>{summary.total}</span>
          )}
        </div>

        {/* Severity filter pills */}
        <div style={{ display: 'flex', gap: 6, marginBottom: 12 }}>
          {pills.map(p => {
            const active = sevFilter === p.key;
            const sc = SEV_COLORS[p.key];
            const style = active && sc
              ? { background: sc.bg, borderColor: sc.bd, color: sc.color }
              : active
                ? { background: 'var(--bgH)', borderColor: 'var(--bdL)', color: 'var(--tx)' }
                : {};
            return (
              <button key={p.key} onClick={() => setSevFilter(p.key)} style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '5px 12px', borderRadius: 'var(--rs)',
                border: '1px solid var(--bd)', background: 'var(--bgC)',
                color: 'var(--txM)', fontSize: 10.5, cursor: 'pointer',
                transition: 'all .13s', userSelect: 'none', fontFamily: 'var(--fn)',
                ...style,
              }}>
                {sc && <span style={{ width: 6, height: 6, borderRadius: '50%', background: sc.color }} />}
                <span style={{ fontWeight: 600 }}>{p.label}</span>
                <span style={{ opacity: .75 }}>{p.count}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Search / sort row */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '0 18px 12px', flexShrink: 0,
        borderBottom: '1px solid var(--bd)',
      }}>
        <div style={{
          display: 'flex', alignItems: 'center', gap: 7,
          background: 'var(--bgC)', border: '1px solid var(--bd)',
          borderRadius: 'var(--rs)', padding: '5px 10px', flex: 1,
        }}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--txD)" strokeWidth="2">
            <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
          </svg>
          <input
            placeholder="Filter by IP, detector, protocol, port..."
            value={search} onChange={e => setSearch(e.target.value)}
            style={{
              background: 'none', border: 'none', outline: 'none',
              color: 'var(--tx)', fontFamily: 'var(--fn)', fontSize: 11, width: '100%',
            }}
          />
          {search && (
            <button onClick={() => setSearch('')} style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--txD)', fontSize: 13, padding: 0, lineHeight: 1,
            }}>×</button>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
          <span style={{ color: 'var(--txD)', fontSize: 10.5 }}>Sort</span>
          <select value={sortBy} onChange={e => setSortBy(e.target.value)} style={{
            background: 'var(--bgC)', border: '1px solid var(--bd)',
            color: 'var(--txM)', fontFamily: 'var(--fn)', fontSize: 10.5,
            borderRadius: 'var(--rs)', padding: '4px 8px', cursor: 'pointer', outline: 'none',
          }}>
            <option value="severity">Severity</option>
            <option value="time">Time</option>
            <option value="detector">Detector</option>
          </select>
        </div>
      </div>

      {/* Alert list */}
      <div style={{
        flex: 1, overflowY: 'auto',
        padding: '10px 18px 18px',
        display: 'flex', flexDirection: 'column', gap: 5,
      }}>
        {sorted.length === 0 && (
          <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--txD)', fontSize: 12 }}>
            {alerts.length === 0
              ? 'No alerts detected in this capture.'
              : 'No alerts match the current filters.'}
          </div>
        )}

        {groups ? (
          // Severity-grouped with section dividers
          SEV_ORDER.filter(sev => groups[sev]?.length > 0).map(sev => (
            <React.Fragment key={sev}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 0 2px' }}>
                <span style={{
                  fontSize: 9.5, fontWeight: 700, letterSpacing: '.1em',
                  textTransform: 'uppercase', color: SEV_COLORS[sev]?.color || 'var(--txD)',
                  whiteSpace: 'nowrap',
                }}>{sev} ({groups[sev].length})</span>
                <div style={{ flex: 1, height: 1, background: 'var(--bd)' }} />
              </div>
              {groups[sev].map(renderCard)}
            </React.Fragment>
          ))
        ) : (
          // Flat list for time/detector sort
          sorted.map(renderCard)
        )}
      </div>
    </div>
  );
}
