import React from 'react';
import { fN, fB } from '../utils';

export default function LeftPanel({
  protocols, pColors, enabledP, setEnabledP, graph, stats,
  rPanel, switchPanel, selNodes, clearSel, selEdge, selSession,
  sessionTotal = 0, sessionFiltered = 0, activeSearch = '',
  subnetG, setSubnetG, toggleSubnetG, subnetPrefix = 24, setSubnetPrefix,
  mergeByMac, setMergeByMac,
  includeIPv6 = true, setIncludeIPv6,
  showHostnames = true, setShowHostnames,
  labelThreshold = 0, setLabelThreshold,
  // osGuesses + onApplyDisplayFilter kept as props but OS filter moved to FilterBar chips
  onApplyDisplayFilter, activeOsFilter, osGuesses = [],
}) {
  return (
    <div style={{
      width: 170, background: 'var(--bgP)', borderRight: '1px solid var(--bd)',
      overflowY: 'auto', flexShrink: 0, padding: '10px',
    }}>
      {/* Protocol toggles */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <div className="sh" style={{ marginBottom: 0 }}>Protocols</div>
        <div style={{ display: 'flex', gap: 2 }}>
          <button className="btn" style={{ padding: '1px 6px', fontSize: 9 }}
            onClick={() => setEnabledP(new Set(protocols))}>All</button>
          <button className="btn" style={{ padding: '1px 6px', fontSize: 9 }}
            onClick={() => setEnabledP(new Set())}>None</button>
        </div>
      </div>

      {protocols.filter(p => p && p.trim()).map(p => {
        const on = enabledP.has(p);
        const col = pColors[p] || '#64748b';
        return (
          <div key={p} onClick={() => {
            const n = new Set(enabledP);
            if (n.has(p)) n.delete(p); else n.add(p);
            setEnabledP(n);
          }}
            style={{
              display: 'flex', alignItems: 'center', gap: 7, padding: '4px',
              borderRadius: 3, cursor: 'pointer', opacity: on ? 1 : 0.3,
              fontSize: 11, transition: 'all .15s',
            }}>
            <span style={{
              width: 10, height: 10, borderRadius: 3,
              background: on ? col : 'transparent',
              border: '1.5px solid ' + col, flexShrink: 0,
            }} />
            <span style={{ fontWeight: on ? 500 : 400 }}>{p}</span>
            <span style={{ marginLeft: 'auto', color: 'var(--txD)', fontSize: 9 }}>
              {stats?.protocols?.[p]?.packets || ''}
            </span>
          </div>
        );
      })}

      {/* Panel switcher */}
      <div style={{ borderTop: '1px solid var(--bd)', marginTop: 10, paddingTop: 10 }}>
        <div className="sh">Panel</div>
        {[['stats', 'Overview'], ['sessions', 'Sessions'], ['timeline', 'Timeline'], ['research', 'Research'], ['analysis', 'Analysis ✦'], ['investigation', 'Investigation'], ['visualize', 'Visualize'], ['logs', 'Server Logs'], ['help', 'Help']].map(([k, l]) => {
          const isActive = rPanel === k && !selNodes.length && !selEdge && !selSession;
          const showBadge = k === 'sessions' && activeSearch && sessionTotal > 0 && sessionFiltered !== sessionTotal;
          return (
            <div key={k} onClick={() => switchPanel(k)} style={{
              padding: '5px 6px', borderRadius: 'var(--rs)', cursor: 'pointer', fontSize: 11,
              background: isActive ? 'rgba(88,166,255,.08)' : 'transparent',
              color: isActive ? 'var(--ac)' : 'var(--txM)',
              marginBottom: 2, display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            }}>
              <span>{l}</span>
              {showBadge && (
                <span style={{
                  fontSize: 8, fontFamily: 'var(--fn)',
                  color: isActive ? 'var(--ac)' : 'var(--txD)',
                  background: 'var(--bgC)', borderRadius: 8, padding: '1px 5px',
                  border: '1px solid var(--bd)', flexShrink: 0,
                }}>{sessionFiltered}/{sessionTotal}</span>
              )}
              {k === 'visualize' && (
                <span style={{
                  fontSize: 7, letterSpacing: '.05em', padding: '0px 4px', borderRadius: 6,
                  background: 'rgba(251,191,36,.12)', color: '#fbbf24',
                  border: '1px solid rgba(251,191,36,.3)', flexShrink: 0,
                }}>BETA</span>
              )}
            </div>
          );
        })}
      </div>

      {/* Graph Options */}
      <div style={{ borderTop: '1px solid var(--bd)', marginTop: 10, paddingTop: 10 }}>
        <div className="sh">Graph Options</div>

        {/* Subnet grouping with prefix selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px', borderRadius: 3 }}>
          <span
            onClick={() => toggleSubnetG ? toggleSubnetG() : setSubnetG(!subnetG)}
            title="Group IPs into subnets"
            style={{ display: 'flex', alignItems: 'center', gap: 7, cursor: 'pointer', flex: 1, opacity: subnetG ? 1 : 0.45, transition: 'all .15s' }}>
            <span style={{
              width: 10, height: 10, borderRadius: 2, flexShrink: 0,
              background: subnetG ? 'var(--ac)' : 'transparent',
              border: '1.5px solid ' + (subnetG ? 'var(--ac)' : 'var(--txD)'),
              transition: 'all .15s',
            }} />
            <span style={{ fontSize: 11, fontWeight: subnetG ? 500 : 400 }}>Subnet</span>
          </span>
          <span style={{ fontSize: 9, color: 'var(--txD)' }}>/</span>
          <input
            type="number" min={8} max={32} value={subnetPrefix}
            onChange={e => setSubnetPrefix(Math.max(8, Math.min(32, +e.target.value)))}
            title="Subnet prefix length (8–32)"
            style={{
              width: 36, fontSize: 10, fontFamily: 'var(--fn)',
              background: 'var(--bgI)', border: '1px solid var(--bd)',
              borderRadius: 3, color: 'var(--tx)', padding: '1px 4px', textAlign: 'center',
            }}
          />
        </div>

        {/* Merge + IPv6 toggles */}
        {[
          [mergeByMac,    setMergeByMac,    'Merge by MAC',   'Merge IPs sharing a MAC address into one node'],
          [includeIPv6,   setIncludeIPv6,  'Show IPv6',       'Toggle off to hide IPv6 nodes (fe80::, ff02::, etc.) and reduce noise in dual-stack captures'],
          [showHostnames, setShowHostnames, 'Show hostnames',  'Show DNS-resolved hostnames as node labels (cyan). Toggle off to always show raw IP addresses.'],
        ].map(([val, setter, label, tip]) => (
          <div key={label}
            onClick={() => setter(!val)}
            title={tip}
            style={{
              display: 'flex', alignItems: 'center', gap: 7, padding: '4px',
              borderRadius: 3, cursor: 'pointer', fontSize: 11,
              opacity: val ? 1 : 0.45, transition: 'all .15s',
            }}>
            <span style={{
              width: 10, height: 10, borderRadius: 2, flexShrink: 0,
              background: val ? 'var(--ac)' : 'transparent',
              border: '1.5px solid ' + (val ? 'var(--ac)' : 'var(--txD)'),
              transition: 'all .15s',
            }} />
            <span style={{ fontWeight: val ? 500 : 400 }}>{label}</span>
          </div>
        ))}

        {/* Label threshold */}
        {setLabelThreshold && (() => {
          // Preset steps: 0 (off), 1KB, 10KB, 100KB, 1MB, 10MB
          const STEPS = [0, 1024, 10240, 102400, 1048576, 10485760];
          const stepIdx = STEPS.reduce((best, v, i) => Math.abs(v - labelThreshold) < Math.abs(STEPS[best] - labelThreshold) ? i : best, 0);
          return (
            <div style={{ marginTop: 8, padding: '4px' }}
              title="Hide node labels below this traffic threshold. Hover a node to always see its label.">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 3 }}>
                <span style={{ fontSize: 11, color: labelThreshold > 0 ? 'var(--tx)' : 'var(--txD)', fontWeight: labelThreshold > 0 ? 500 : 400 }}>
                  Label threshold
                </span>
                {labelThreshold > 0 && (
                  <button className="btn" onClick={() => setLabelThreshold(0)}
                    style={{ fontSize: 8, padding: '0 4px' }}>off</button>
                )}
              </div>
              <input type="range" min={0} max={STEPS.length - 1} step={1}
                value={stepIdx}
                onChange={e => setLabelThreshold(STEPS[+e.target.value])}
                style={{ width: '100%' }} />
              <div style={{ fontSize: 9, color: 'var(--txD)', marginTop: 2 }}>
                {labelThreshold === 0 ? 'Show all labels' : `≥ ${fB(labelThreshold)}`}
              </div>
            </div>
          );
        })()}
      </div>

      {/* View info */}
      <div style={{ borderTop: '1px solid var(--bd)', marginTop: 10, paddingTop: 10 }}>
        <div className="sh">View Info</div>
        <div style={{ fontSize: 10, color: 'var(--txD)', lineHeight: 1.7 }}>
          Nodes: {graph.nodes?.length || 0}<br />
          Edges: {graph.edges?.length || 0}<br />
          Packets in view: {fN(graph.filtered_count || 0)}<br />
          {graph.filtered_bytes > 0 && <>Data in view: {fB(graph.filtered_bytes)}</>}
        </div>
      </div>

      {/* Multi-select info */}
      {selNodes.length > 1 && (
        <div style={{ borderTop: '1px solid var(--bd)', marginTop: 10, paddingTop: 10 }}>
          <div className="sh">Multi-select</div>
          <div style={{ fontSize: 10, color: 'var(--txD)' }}>
            {selNodes.length} nodes selected<br />
            <span style={{ fontSize: 9, color: 'var(--txM)' }}>Shift+click to add/remove</span>
          </div>
          <button className="btn" onClick={clearSel} style={{ marginTop: 6, fontSize: 9 }}>Clear all</button>
        </div>
      )}
    </div>
  );
}
