import { useMemo } from 'react';
import Collapse from '../../core/components/Collapse';
import Tag from '../../core/components/Tag';
import { useWorkspace } from '@/WorkspaceProvider';

// ── Helpers ───────────────────────────────────────────────────────────────────

function fN(n) {
  if (n == null) return '—';
  return n >= 1e6 ? (n / 1e6).toFixed(1) + 'M'
    : n >= 1e3 ? (n / 1e3).toFixed(1) + 'K'
    : String(n);
}

function formatTs(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'; }
  catch { return iso; }
}

function formatDuration(first, last) {
  if (!first || !last) return null;
  const ms = new Date(last) - new Date(first);
  if (ms <= 0) return null;
  const h = Math.floor(ms / 3600000);
  const m = Math.floor((ms % 3600000) / 60000);
  const s = Math.floor((ms % 60000) / 1000);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

// ── Sub-components ────────────────────────────────────────────────────────────

function MetricTile({ value, label, color }) {
  return (
    <div style={{
      background: 'var(--bgC)', border: '1px solid var(--bd)', borderRadius: 6,
      padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 3,
    }}>
      <div style={{
        fontSize: 20, fontWeight: 700, fontFamily: 'var(--fd)',
        color: color || 'var(--tx)', lineHeight: 1,
      }}>{value}</div>
      <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.07em' }}>
        {label}
      </div>
    </div>
  );
}

function MiniBar({ items, color = 'rgba(88,166,255,.35)', onSelect }) {
  if (!items?.length) return <div style={{ fontSize: 10, color: 'var(--txD)' }}>No data</div>;
  const maxVal = Math.max(...items.map(d => d.value), 1);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      {items.map((item, i) => (
        <div
          key={i}
          onClick={() => onSelect?.(item)}
          style={{
            display: 'flex', alignItems: 'center', gap: 8, fontSize: 10,
            cursor: onSelect ? 'pointer' : 'default', padding: '2px 4px', borderRadius: 3,
          }}
          onMouseOver={e => { if (onSelect) e.currentTarget.style.background = 'rgba(255,255,255,.04)'; }}
          onMouseOut={e => { e.currentTarget.style.background = 'transparent'; }}
        >
          <span style={{
            fontFamily: 'var(--fn)', color: onSelect ? 'var(--ac)' : 'var(--txM)',
            width: 130, flexShrink: 0, overflow: 'hidden',
            textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 10,
          }}>{item.label}</span>
          <div style={{ flex: 1, height: 8, background: 'var(--bgC)', borderRadius: 2, overflow: 'hidden' }}>
            <div style={{
              width: `${(item.value / maxVal) * 100}%`, height: '100%',
              background: color, borderRadius: 2, minWidth: item.value > 0 ? 2 : 0,
            }} />
          </div>
          <span style={{ fontSize: 9, color: 'var(--txD)', width: 32, textAlign: 'right', flexShrink: 0 }}>
            {fN(item.value)}
          </span>
        </div>
      ))}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function ForensicStatsPanel({ nodes = [], edges = [], stats = {}, onSelectNode, loaded }) {
  const workspace = useWorkspace();

  // Edge type → schema meta
  const edgeMetaByName = useMemo(() => {
    const m = {};
    for (const et of (workspace.schema?.edge_types || [])) m[et.name] = et;
    return m;
  }, [workspace.schema]);

  // Node type → schema meta
  const nodeMetaByName = useMemo(() => {
    const m = {};
    for (const nt of (workspace.schema?.node_types || [])) m[nt.name] = nt;
    return m;
  }, [workspace.schema]);

  // Derived counts
  const derived = useMemo(() => {
    const byNodeType = {};
    for (const n of nodes) byNodeType[n.type] = (byNodeType[n.type] || 0) + 1;

    const byEdgeType = {};
    let totalEvents = 0;
    let tsFirst = null, tsLast = null;
    for (const e of edges) {
      const cnt = e.event_count || 0;
      byEdgeType[e.type] = (byEdgeType[e.type] || 0) + cnt;
      totalEvents += cnt;
      if (e.ts_first && (!tsFirst || e.ts_first < tsFirst)) tsFirst = e.ts_first;
      if (e.ts_last  && (!tsLast  || e.ts_last  > tsLast))  tsLast  = e.ts_last;
    }

    // Top processes by event_count
    const topProcesses = nodes
      .filter(n => n.type === 'process')
      .sort((a, b) => (b.event_count || 0) - (a.event_count || 0))
      .slice(0, 8)
      .map(n => ({ id: n.id, label: n.image || n.label || n.id, value: n.event_count || 0 }));

    // Top endpoints by connection_count (or event_count)
    const topEndpoints = nodes
      .filter(n => n.type === 'endpoint')
      .sort((a, b) => (b.event_count || 0) - (a.event_count || 0))
      .slice(0, 8)
      .map(n => ({ id: n.id, label: n.hostname || n.ip || n.label || n.id, value: n.event_count || 0 }));

    return { byNodeType, byEdgeType, totalEvents, tsFirst, tsLast, topProcesses, topEndpoints };
  }, [nodes, edges]);

  if (!loaded) {
    return (
      <div className="fi" style={{ padding: 16, color: 'var(--txD)', fontSize: 11 }}>
        No artifacts loaded. Upload an EVTX, ZIP, or CSV to begin.
      </div>
    );
  }

  const { byNodeType, byEdgeType, totalEvents, tsFirst, tsLast, topProcesses, topEndpoints } = derived;
  const duration = formatDuration(tsFirst, tsLast);

  // Metric tiles
  const processCount  = byNodeType.process  || 0;
  const endpointCount = byNodeType.endpoint || 0;
  const fileCount     = byNodeType.file     || 0;
  const regCount      = byNodeType.registry || 0;

  // Event type bars — sorted by count
  const edgeTypeBars = Object.entries(byEdgeType)
    .filter(([, v]) => v > 0)
    .sort(([, a], [, b]) => b - a)
    .map(([type, value]) => {
      const meta = edgeMetaByName[type];
      return { label: meta?.label || type, value, color: meta?.color || '#8b949e' };
    });

  return (
    <div className="fi" style={{ padding: 16, overflowY: 'auto', height: '100%' }}>

      <div className="sh" style={{ marginBottom: 12 }}>Overview</div>

      {/* Metric tiles 2×2 */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginBottom: 14 }}>
        <MetricTile value={fN(totalEvents || stats.event_count || 0)} label="Events" color="var(--ac)" />
        <MetricTile value={fN(processCount)} label="Processes" color="#4fc3f7" />
        <MetricTile value={fN(endpointCount)} label="Endpoints" color="#ce93d8" />
        <MetricTile value={fN(fileCount + regCount)} label="Files + Registry" color="#fff176" />
      </div>

      {/* Time range */}
      {(tsFirst || tsLast) && (
        <div style={{
          background: 'var(--bgC)', border: '1px solid var(--bd)', borderRadius: 5,
          padding: '8px 10px', marginBottom: 14, fontSize: 10,
        }}>
          <div style={{
            fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase',
            letterSpacing: '.07em', marginBottom: 5,
          }}>Activity Window</div>
          {tsFirst && (
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
              <span style={{ color: 'var(--txD)' }}>First</span>
              <span style={{ color: 'var(--txM)', fontFamily: 'var(--fn)', fontSize: 9 }}>{formatTs(tsFirst)}</span>
            </div>
          )}
          {tsLast && (
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
              <span style={{ color: 'var(--txD)' }}>Last</span>
              <span style={{ color: 'var(--txM)', fontFamily: 'var(--fn)', fontSize: 9 }}>{formatTs(tsLast)}</span>
            </div>
          )}
          {duration && (
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--txD)' }}>Duration</span>
              <span style={{ color: 'var(--ac)', fontFamily: 'var(--fn)', fontSize: 9, fontWeight: 600 }}>{duration}</span>
            </div>
          )}
        </div>
      )}

      {/* Event type breakdown */}
      {edgeTypeBars.length > 0 && (
        <Collapse title="Events by Type" open>
          {edgeTypeBars.map(({ label, value, color }) => (
            <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5 }}>
              <Tag color={color} small>{label}</Tag>
              <div style={{ flex: 1, height: 8, background: 'var(--bgC)', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{
                  width: `${(value / Math.max(...edgeTypeBars.map(b => b.value), 1)) * 100}%`,
                  height: '100%', background: color + '55', borderRadius: 2, minWidth: 2,
                }} />
              </div>
              <span style={{ fontSize: 9, color: 'var(--txD)', width: 28, textAlign: 'right', flexShrink: 0 }}>
                {fN(value)}
              </span>
            </div>
          ))}
        </Collapse>
      )}

      {/* Top processes */}
      {topProcesses.length > 0 && (
        <Collapse title={`Top Processes (${topProcesses.length})`} open>
          <MiniBar
            items={topProcesses}
            color="rgba(79,195,247,.35)"
            onSelect={item => onSelectNode?.(item.id)}
          />
        </Collapse>
      )}

      {/* Top endpoints */}
      {topEndpoints.length > 0 && (
        <Collapse title={`Top Endpoints (${topEndpoints.length})`} open>
          <MiniBar
            items={topEndpoints}
            color="rgba(206,147,216,.35)"
            onSelect={item => onSelectNode?.(item.id)}
          />
        </Collapse>
      )}

    </div>
  );
}
