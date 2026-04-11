import React, { useState, useMemo } from 'react';
import { fN } from '../utils';

export default function LeftPanel({
  protocols, pColors, enabledP, setEnabledP, graph, stats,
  rPanel, switchPanel, selNodes, clearSel, selEdge, selSession,
  sessionTotal = 0, sessionFiltered = 0, activeSearch = '',
  onApplyDisplayFilter, activeOsFilter, osGuesses = [],
  queryActive = false,
  alertSummary = {},
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
          <button className="btn" style={{ padding: '1px 6px', fontSize: 10 }}
            onClick={() => setEnabledP(new Set(allKeys))}>All</button>
          <button className="btn" style={{ padding: '1px 6px', fontSize: 10 }}
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
                <span style={{ marginLeft: 'auto', color: 'var(--txD)', fontSize: 9, fontFamily: 'var(--fn)' }}>{fN(tEntry.totalPackets)}</span>
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
              <span style={{ fontSize: 9, color: 'var(--txD)', width: 10, textAlign: 'center', flexShrink: 0, userSelect: 'none' }}>
                {ipCollapsed ? '▸' : '▾'}
              </span>
              <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--txM)', flex: 1 }}>{ipGroup.label}</span>
              <span style={{ fontSize: 9, color: 'var(--txD)', fontFamily: 'var(--fn)' }}>{fN(ipGroup.totalPackets)}</span>
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
                      <span onClick={() => toggle(tKey)} style={{ fontSize: 9, color: 'var(--txD)', width: 10, textAlign: 'center', flexShrink: 0, userSelect: 'none' }}>
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
                    <span style={{ fontSize: 9, color: 'var(--txD)', fontFamily: 'var(--fn)' }}>{fN(tEntry.totalPackets)}</span>
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
                        <span style={{ marginLeft: 'auto', color: 'var(--txD)', fontSize: 9, fontFamily: 'var(--fn)' }}>{fN(leaf.packets)}</span>
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
        {[
          { label: 'Data',      items: [['stats','Overview'],['sessions','Sessions'],['timeline','Timeline']] },
          { label: 'Analysis',  items: [['query','Query'],['research','Research'],['analysis','Analysis ✦'],['alerts','Alerts']] },
          { label: 'Workspace', items: [['investigation','Investigation'],['visualize','Visualize']] },
          { label: 'Settings',  items: [['graph-options','Graph Options'],['logs','Server Logs'],['help','Help']] },
        ].map(({ label, items }) => (
          <div key={label} style={{ marginBottom: 4 }}>
            <div style={{
              fontSize: 9, color: 'var(--txD)', letterSpacing: '.06em',
              textTransform: 'uppercase', padding: '4px 6px 2px', userSelect: 'none',
            }}>{label}</div>
            {items.map(([k, l]) => {
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
                      fontSize: 9, fontFamily: 'var(--fn)',
                      color: isActive ? 'var(--ac)' : 'var(--txD)',
                      background: 'var(--bgC)', borderRadius: 8, padding: '1px 5px',
                      border: '1px solid var(--bd)', flexShrink: 0,
                    }}>{sessionFiltered}/{sessionTotal}</span>
                  )}
                  {k === 'query' && queryActive && (
                    <span style={{
                      width: 6, height: 6, borderRadius: '50%',
                      background: '#f0883e', flexShrink: 0,
                    }} />
                  )}
                  {k === 'alerts' && (() => {
                    const ac = (alertSummary.high || 0) + (alertSummary.medium || 0);
                    return ac > 0 ? (
                      <span style={{
                        fontSize: 9, fontFamily: 'var(--fn)', fontWeight: 700,
                        color: '#f85149',
                        background: 'rgba(248,81,73,.10)', borderRadius: 10, padding: '1px 6px',
                        border: '1px solid rgba(248,81,73,.28)', flexShrink: 0,
                      }}>{ac}</span>
                    ) : null;
                  })()}
                  {k === 'visualize' && (
                    <span style={{
                      fontSize: 9, letterSpacing: '.05em', padding: '0px 4px', borderRadius: 6,
                      background: 'rgba(251,191,36,.12)', color: '#fbbf24',
                      border: '1px solid rgba(251,191,36,.3)', flexShrink: 0,
                    }}>BETA</span>
                  )}
                </div>
              );
            })}
          </div>
        ))}
      </div>

    </div>
  );
}
