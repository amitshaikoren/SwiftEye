import React, { useState, useMemo } from 'react';
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
  onApplyDisplayFilter, activeOsFilter, osGuesses = [],
}) {
  const [collapsed, setCollapsed] = useState({});
  const toggle = k => setCollapsed(c => ({ ...c, [k]: !c[k] }));

  // Build protocol hierarchy tree from stats.
  // Each leaf is a composite key "ipv/transport/protocol" e.g. "4/TCP/HTTPS".
  // enabledP is a Set of these composite keys.
  const { tree, allKeys } = useMemo(() => {
    const sp = stats?.protocols || {};
    const ipGroups = {};
    const allKeys = [];
    // Non-IP protocols that should be top-level, not under IPv4/IPv6
    const nonIpTransports = new Set(['ARP', 'OTHER']);

    for (const pName of protocols.filter(p => p && p.trim())) {
      const info = sp[pName] || {};
      const transport = info.transport || pName;
      const v4 = info.ipv4 || 0;
      const v6 = info.ipv6 || 0;
      const total = info.packets || 0;

      // Non-IP protocols: top-level group keyed by transport name
      if (nonIpTransports.has(transport)) {
        const ipv = transport; // use transport name as the group key
        const key = `0/${transport}/${pName}`;
        if (!ipGroups[ipv]) ipGroups[ipv] = {};
        if (!ipGroups[ipv][transport]) ipGroups[ipv][transport] = [];
        ipGroups[ipv][transport].push({ name: pName, key, packets: total });
        allKeys.push(key);
        continue;
      }

      if (v4 > 0 || (v6 === 0 && total > 0)) {
        const ipv = '4';
        const key = `${ipv}/${transport}/${pName}`;
        if (!ipGroups[ipv]) ipGroups[ipv] = {};
        if (!ipGroups[ipv][transport]) ipGroups[ipv][transport] = [];
        ipGroups[ipv][transport].push({ name: pName, key, packets: v4 || total });
        allKeys.push(key);
      }
      if (v6 > 0) {
        const ipv = '6';
        const key = `${ipv}/${transport}/${pName}`;
        if (!ipGroups[ipv]) ipGroups[ipv] = {};
        if (!ipGroups[ipv][transport]) ipGroups[ipv][transport] = [];
        ipGroups[ipv][transport].push({ name: pName, key, packets: v6 });
        allKeys.push(key);
      }
    }

    const tree = [];
    const ipLabels = { '4': 'IPv4', '6': 'IPv6' };
    for (const [ipv, transports] of Object.entries(ipGroups)) {
      const tEntries = Object.entries(transports)
        .map(([t, leaves]) => {
          // Rename leaves where protocol == transport to "Other" for display
          const displayLeaves = leaves.map(l => ({
            ...l,
            displayName: l.name === t ? 'Other' : l.name,
          })).sort((a, b) => {
            // "Other" always last
            if (a.displayName === 'Other') return 1;
            if (b.displayName === 'Other') return -1;
            return b.packets - a.packets;
          });
          return {
            transport: t,
            leaves: displayLeaves,
            totalPackets: displayLeaves.reduce((s, l) => s + l.packets, 0),
            keys: displayLeaves.map(l => l.key),
          };
        })
        .filter(e => e.totalPackets > 0)
        .sort((a, b) => b.totalPackets - a.totalPackets);
      if (tEntries.length > 0) {
        const allIpKeys = tEntries.flatMap(t => t.keys);
        tree.push({
          ipVersion: ipv, label: ipLabels[ipv] || ipv,
          transports: tEntries,
          totalPackets: tEntries.reduce((s, t) => s + t.totalPackets, 0),
          keys: allIpKeys,
        });
      }
    }
    return { tree, allKeys };
  }, [protocols, stats]);

  // Toggle helpers
  const toggleKeys = (keys, allOn) => {
    const n = new Set(enabledP);
    keys.forEach(k => allOn ? n.delete(k) : n.add(k));
    setEnabledP(n);
  };
  const soloKeys = (keys) => setEnabledP(new Set(keys));

  return (
    <div style={{
      width: 170, background: 'var(--bgP)', borderRight: '1px solid var(--bd)',
      overflowY: 'auto', flexShrink: 0, padding: '10px',
    }}>
      {/* Protocol tree */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <div className="sh" style={{ marginBottom: 0 }}>Protocols</div>
        <div style={{ display: 'flex', gap: 2 }}>
          <button className="btn" style={{ padding: '1px 6px', fontSize: 9 }}
            onClick={() => setEnabledP(new Set(allKeys))}>All</button>
          <button className="btn" style={{ padding: '1px 6px', fontSize: 9 }}
            onClick={() => setEnabledP(new Set())}>None</button>
        </div>
      </div>

      {tree.map(ipGroup => {
        const ipCollapsed = collapsed[ipGroup.ipVersion];
        const isIpGroup = ipGroup.ipVersion === '4' || ipGroup.ipVersion === '6';

        // Non-IP groups (ARP, OTHER) — render as flat toggleable rows with color swatches
        if (!isIpGroup) {
          return ipGroup.transports.map(tEntry => {
            const allTOn = tEntry.keys.every(k => enabledP.has(k));
            const col = pColors[tEntry.transport] || '#64748b';
            return (
              <div key={tEntry.transport}
                onClick={() => toggleKeys(tEntry.keys, allTOn)}
                onDoubleClick={(e) => { e.stopPropagation(); soloKeys(tEntry.keys); }}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6, padding: '2px 0',
                  cursor: 'pointer', opacity: allTOn ? 1 : 0.3, fontSize: 10, transition: 'opacity .15s',
                }}>
                <span style={{
                  width: 8, height: 8, borderRadius: 2, flexShrink: 0,
                  background: allTOn ? col : 'transparent',
                  border: '1.5px solid ' + col,
                }} />
                <span style={{ fontWeight: allTOn ? 500 : 400 }}>{tEntry.transport}</span>
                <span style={{ marginLeft: 'auto', color: 'var(--txD)', fontSize: 8, fontFamily: 'var(--fn)' }}>{fN(tEntry.totalPackets)}</span>
              </div>
            );
          });
        }

        // IP groups (IPv4, IPv6) — collapsible header with transport children
        return (
          <div key={ipGroup.ipVersion} style={{ marginBottom: 2 }}>
            {/* IP version header — collapse only */}
            <div onClick={() => toggle(ipGroup.ipVersion)}
              style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '3px 0', cursor: 'pointer' }}>
              <span style={{ fontSize: 8, color: 'var(--txD)', width: 10, textAlign: 'center', flexShrink: 0, userSelect: 'none' }}>
                {ipCollapsed ? '▸' : '▾'}
              </span>
              <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--txM)', flex: 1 }}>{ipGroup.label}</span>
              <span style={{ fontSize: 8, color: 'var(--txD)', fontFamily: 'var(--fn)' }}>{fN(ipGroup.totalPackets)}</span>
            </div>

            {!ipCollapsed && ipGroup.transports.map(tEntry => {
              const tKey = ipGroup.ipVersion + '/' + tEntry.transport;
              const tCollapsed = collapsed[tKey];
              const allTOn = tEntry.keys.every(k => enabledP.has(k));
              const someOn = tEntry.keys.some(k => enabledP.has(k));
              const hasChildren = tEntry.leaves.length > 1 || (tEntry.leaves[0]?.displayName !== 'Other' && tEntry.leaves[0]?.displayName !== tEntry.transport);
              const tCol = pColors[tEntry.transport] || '#64748b';

              return (
                <div key={tKey} style={{ marginLeft: 10 }}>
                  {/* Transport row — with color swatch for click affordance */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '2px 0', cursor: 'pointer' }}>
                    {hasChildren ? (
                      <span onClick={() => toggle(tKey)} style={{ fontSize: 8, color: 'var(--txD)', width: 10, textAlign: 'center', flexShrink: 0, userSelect: 'none' }}>
                        {tCollapsed ? '▸' : '▾'}
                      </span>
                    ) : (
                      <span style={{ width: 10 }} />
                    )}
                    <span onClick={() => toggleKeys(tEntry.keys, allTOn)}
                      onDoubleClick={(e) => { e.stopPropagation(); soloKeys(tEntry.keys); }}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 5, flex: 1,
                        opacity: allTOn ? 1 : someOn ? 0.65 : 0.3, transition: 'opacity .15s',
                      }}>
                      <span style={{
                        width: 8, height: 8, borderRadius: 2, flexShrink: 0,
                        background: allTOn ? tCol : someOn ? tCol : 'transparent',
                        border: '1.5px solid ' + tCol,
                        opacity: someOn && !allTOn ? 0.5 : 1,
                      }} />
                      <span style={{ fontSize: 10, fontWeight: 500, color: 'var(--txM)' }}>
                        {tEntry.transport}
                      </span>
                    </span>
                    <span style={{ fontSize: 8, color: 'var(--txD)', fontFamily: 'var(--fn)' }}>{fN(tEntry.totalPackets)}</span>
                  </div>

                  {/* Leaves — only show if transport has app-level protocols beneath it */}
                  {!tCollapsed && hasChildren && tEntry.leaves.map(leaf => {
                    const on = enabledP.has(leaf.key);
                    const col = pColors[leaf.name] || '#64748b';
                    const isOther = leaf.displayName === 'Other';
                    return (
                      <div key={leaf.key}
                        onClick={() => toggleKeys([leaf.key], on)}
                        onDoubleClick={(e) => { e.stopPropagation(); soloKeys([leaf.key]); }}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 6, padding: '2px 0 2px 20px',
                          cursor: 'pointer', opacity: on ? 1 : 0.3, fontSize: 10, transition: 'opacity .15s',
                        }}>
                        <span style={{
                          width: 8, height: 8, borderRadius: 2, flexShrink: 0,
                          background: on ? col : 'transparent',
                          border: '1.5px solid ' + col,
                        }} />
                        <span style={{ fontWeight: on ? 500 : 400, fontStyle: isOther ? 'italic' : 'normal', color: isOther ? 'var(--txD)' : undefined }}>{leaf.displayName}</span>
                        <span style={{ marginLeft: 'auto', color: 'var(--txD)', fontSize: 8, fontFamily: 'var(--fn)' }}>{fN(leaf.packets)}</span>
                      </div>
                    );
                  })}
                </div>
              );
            })}
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
