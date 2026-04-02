import React, { useState, useEffect, useCallback, useMemo } from 'react';
import ScopePill from './ScopePill';
import Tag from './Tag';
import Collapse from './Collapse';
import Row from './Row';
import { PluginSections, GenericDisplay } from './PluginSection';
import { fN, fB, fD } from '../utils';

/**
 * Classify an IP address into its address type.
 * Returns {label, bg, fg} or null for regular public unicast.
 */
function classifyIp(ip) {
  if (!ip) return null;
  // IPv6
  if (ip.includes(':')) {
    const lower = ip.toLowerCase();
    if (lower === '::1') return { label: 'Loopback', bg: 'rgba(139,148,158,.18)', fg: '#8b949e' };
    if (lower.startsWith('fe80:')) return { label: 'Link-local', bg: 'rgba(139,148,158,.18)', fg: '#8b949e' };
    if (lower.startsWith('ff')) return { label: 'Multicast', bg: 'rgba(210,153,34,.15)', fg: '#d29922' };
    if (lower.startsWith('fc') || lower.startsWith('fd')) return { label: 'ULA', bg: 'rgba(56,189,248,.12)', fg: '#38bdf8' };
    if (lower === '::') return { label: 'Unspecified', bg: 'rgba(139,148,158,.18)', fg: '#8b949e' };
    return null;
  }
  // IPv4
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const [a, b, c, d] = parts.map(Number);
  if (a === 10) return { label: 'Private', bg: 'rgba(56,189,248,.12)', fg: '#38bdf8' };
  if (a === 172 && b >= 16 && b <= 31) return { label: 'Private', bg: 'rgba(56,189,248,.12)', fg: '#38bdf8' };
  if (a === 192 && b === 168) return { label: 'Private', bg: 'rgba(56,189,248,.12)', fg: '#38bdf8' };
  if (a === 127) return { label: 'Loopback', bg: 'rgba(139,148,158,.18)', fg: '#8b949e' };
  if (a === 169 && b === 254) return { label: 'APIPA', bg: 'rgba(210,153,34,.15)', fg: '#d29922' };
  if (a >= 224 && a <= 239) return { label: 'Multicast', bg: 'rgba(210,153,34,.15)', fg: '#d29922' };
  if (a === 255 && b === 255 && c === 255 && d === 255) return { label: 'Broadcast', bg: 'rgba(210,153,34,.15)', fg: '#d29922' };
  if (a === 100 && b >= 64 && b <= 127) return { label: 'CGNAT', bg: 'rgba(163,113,247,.15)', fg: '#a371f7' };
  if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113))
    return { label: 'Documentation', bg: 'rgba(139,148,158,.18)', fg: '#8b949e' };
  if (a === 0) return { label: 'Unspecified', bg: 'rgba(139,148,158,.18)', fg: '#8b949e' };
  return null;  // regular public unicast — no badge
}

/** Dedicated renderer for os_fingerprint on node detail */
function OSFingerprintNodeRenderer({ data }) {
  if (!data) {
    return <div style={{ fontSize: 10, color: 'var(--txD)' }}>No SYN packets seen from this host</div>;
  }
  if (!data.guess) {
    if (data._display) return <GenericDisplay display={data._display} />;
    return <div style={{ fontSize: 10, color: 'var(--txD)' }}>No fingerprint available</div>;
  }
  return (
    <>
      <Row l="Guess" v={data.guess} />
      {data.confidence != null && <Row l="Confidence" v={data.confidence + '%'} />}
      {data.ttl != null && <Row l="Initial TTL" v={String(data.ttl)} />}
      {data.window_size != null && <Row l="Window size" v={fN(data.window_size)} />}
      {data.mss != null && <Row l="MSS" v={String(data.mss)} />}
      {data.wscale != null && <Row l="Window Scale" v={String(data.wscale)} />}
      {data.tcp_options?.length > 0 && (
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 4 }}>
          {data.tcp_options.map((o, i) => <Tag key={i} color="#bc8cff">{o}</Tag>)}
        </div>
      )}
      <div style={{ fontSize: 9, color: 'var(--txD)', marginTop: 6 }}>Based on first SYN packet from this host</div>
    </>
  );
}

/** Dedicated renderer for network_role on node detail */
function NetworkRoleRenderer({ data }) {
  // data is the full network_role map (ip -> role_dict); we pick the best role for this node
  if (!data || typeof data !== 'object') {
    return <div style={{ fontSize: 10, color: 'var(--txD)' }}>No network role data</div>;
  }

  // data may already be a single role dict (if NodeDetail pre-sliced it)
  // or the full ip->role map — handle both
  const isRoleDict = data.role !== undefined;
  const nr = isRoleDict ? data : null;

  if (!nr) {
    return <div style={{ fontSize: 10, color: 'var(--txD)' }}>No network role determined</div>;
  }

  const roleColor = { gateway: '#f0883e', lan: '#3fb950', external: '#8b949e', unknown: '#484f58' };
  const roleLabel = { gateway: 'Gateway / Router', lan: 'LAN host', external: 'External', unknown: 'Unknown' };

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
        <span style={{
          fontSize: 10, padding: '1px 8px', borderRadius: 8, fontWeight: 500,
          background: `${roleColor[nr.role] || '#484f58'}22`,
          color: roleColor[nr.role] || '#8b949e',
          border: `1px solid ${roleColor[nr.role] || '#484f58'}44`,
        }}>{roleLabel[nr.role] || nr.role}</span>
      </div>
      {nr.hops != null && nr.hops > 0 && <Row l="Hops from capture" v={String(nr.hops)} />}
      {nr.hops === 0 && nr.role !== 'gateway' && <Row l="Distance" v="Local segment (0 hops)" />}
      {nr.gw_for > 0 && <Row l="Routes for" v={`${nr.gw_for} external IPs`} />}
      {nr.arp_mac && <Row l="ARP-confirmed MAC" v={nr.arp_mac} />}
      {nr.arp_ips?.length > 1 && (
        <Row l="Shares MAC with" v={nr.arp_ips.filter(ip => ip !== nr.arp_mac).slice(0, 4).join(', ')} />
      )}
    </>
  );
}

/** Inline editable field for synthetic nodes */
function EditField({ label, value, onChange, type = 'text', placeholder }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
      <span style={{ fontSize: 9, color: 'var(--txD)', width: 44, flexShrink: 0, textTransform: 'uppercase', letterSpacing: '.06em' }}>{label}</span>
      <input
        type={type}
        value={value}
        placeholder={placeholder}
        onChange={e => onChange(e.target.value)}
        style={{
          flex: 1, background: 'var(--bgC)', border: '1px solid var(--bd)',
          borderRadius: 3, padding: '2px 6px', fontSize: 10,
          fontFamily: type === 'text' ? 'var(--fn)' : undefined,
          color: 'var(--txM)', outline: 'none',
        }}
      />
    </div>
  );
}

/** Horizontal bar chart — label + bar + count */
function MiniBar({ items, formatValue, labelColor = 'var(--txM)', onClick }) {
  if (!items?.length) return <div style={{ fontSize: 10, color: 'var(--txD)' }}>No data</div>;
  const maxVal = Math.max(...items.map(d => d[1]), 1);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      {items.map(([label, value], i) => (
        <div key={i}
          onClick={() => onClick?.(label)}
          style={{
            display: 'flex', alignItems: 'center', gap: 6, fontSize: 10,
            cursor: onClick ? 'pointer' : 'default', borderRadius: 3,
            padding: '1px 0',
          }}
          onMouseOver={e => { if (onClick) e.currentTarget.style.background = 'rgba(255,255,255,.04)'; }}
          onMouseOut={e => { e.currentTarget.style.background = 'transparent'; }}
        >
          <span style={{ fontFamily: 'var(--fn)', color: labelColor, width: 120, flexShrink: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {label}
          </span>
          <div style={{ flex: 1, height: 10, background: 'var(--bgC)', borderRadius: 2, overflow: 'hidden' }}>
            <div style={{
              width: `${(value / maxVal) * 100}%`, height: '100%',
              background: 'rgba(88,166,255,.35)', borderRadius: 2,
              minWidth: value > 0 ? 2 : 0,
            }} />
          </div>
          <span style={{ fontFamily: 'var(--fn)', color: 'var(--txD)', fontSize: 9, width: 48, textAlign: 'right', flexShrink: 0 }}>
            {formatValue ? formatValue(value) : fN(value)}
          </span>
        </div>
      ))}
    </div>
  );
}

/** Node statistics collapsible — port distributions, top neighbors, protocol breakdown */
function NodeStatistics({ node, onSelectNode }) {
  const [section, setSection] = useState('ports');

  const topDst = node.top_dst_ports || [];
  const topSrc = node.top_src_ports || [];
  const topNeigh = node.top_neighbors || [];
  const topProto = node.top_protocols || [];

  const hasData = topDst.length > 0 || topSrc.length > 0 || topNeigh.length > 0 || topProto.length > 0;
  if (!hasData) return null;

  const tabs = [
    topDst.length > 0 || topSrc.length > 0 ? ['ports', 'Ports'] : null,
    topNeigh.length > 0 ? ['neighbors', 'Neighbors'] : null,
    topProto.length > 0 ? ['protocols', 'Protocols'] : null,
  ].filter(Boolean);

  return (
    <Collapse title="Statistics">
      {/* Tab selector */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 8 }}>
        {tabs.map(([key, label], i) => (
          <button key={key} onClick={() => setSection(key)}
            style={{
              fontSize: 9, padding: '3px 10px', cursor: 'pointer',
              background: section === key ? 'rgba(88,166,255,.12)' : 'transparent',
              color: section === key ? 'var(--ac)' : 'var(--txD)',
              border: `1px solid ${section === key ? 'var(--ac)' : 'var(--bd)'}`,
              borderRadius: i === 0 ? 'var(--rs) 0 0 var(--rs)' : i === tabs.length - 1 ? '0 var(--rs) var(--rs) 0' : '0',
              fontWeight: section === key ? 600 : 400,
              borderLeft: i > 0 ? 'none' : undefined,
            }}>
            {label}
          </button>
        ))}
      </div>

      {section === 'ports' && (
        <div>
          {topDst.length > 0 && (
            <>
              <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.05em', marginBottom: 4 }}>
                Destination ports (top {topDst.length})
              </div>
              <MiniBar items={topDst} />
            </>
          )}
          {topSrc.length > 0 && (
            <div style={{ marginTop: topDst.length > 0 ? 10 : 0 }}>
              <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.05em', marginBottom: 4 }}>
                Source ports (top {topSrc.length})
              </div>
              <MiniBar items={topSrc} />
            </div>
          )}
        </div>
      )}

      {section === 'neighbors' && (
        <div>
          <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.05em', marginBottom: 4 }}>
            Top {topNeigh.length} by traffic volume
          </div>
          <MiniBar items={topNeigh} formatValue={fB} labelColor="var(--ac)" onClick={onSelectNode} />
        </div>
      )}

      {section === 'protocols' && (
        <div>
          <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.05em', marginBottom: 4 }}>
            Protocol breakdown by bytes
          </div>
          <MiniBar items={topProto} formatValue={fB} />
        </div>
      )}
    </Collapse>
  );
}

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

function applyDisplayFilter(sessions, filterState) {
  if (!filterState) return sessions;
  const { enabledP, allProtocolCount, search, includeIPv6 } = filterState;
  let result = sessions;
  if (!includeIPv6) {
    result = result.filter(s => !s.src_ip.includes(':') && !s.dst_ip.includes(':'));
  }
  if (enabledP.size > 0 && enabledP.size < allProtocolCount) {
    const appProtos = new Set(Array.from(enabledP).map(k => k.split('/').pop().toUpperCase()));
    result = result.filter(s => appProtos.has((s.protocol || '').toUpperCase()));
  }
  if (search.trim()) {
    const q = search.toLowerCase();
    result = result.filter(s =>
      s.src_ip.toLowerCase().includes(q) ||
      s.dst_ip.toLowerCase().includes(q) ||
      (s.protocol || '').toLowerCase().includes(q) ||
      String(s.src_port).includes(q) ||
      String(s.dst_port).includes(q)
    );
  }
  return result;
}

export default function NodeDetail({
  nodeId, nodes, edges, sessions, pColors, onClear, onSelectNode, onSelectEdge, onSelectSession,
  pluginResults, uiSlots, annotations = [], onSaveNote, onUpdateSynthetic,
  filterState, fullSessions, fullEdges,
}) {
  const node = nodes.find(n => n.id === nodeId);
  const [scope, setScope] = useScopeState('swifteye_scope_node');
  const displaySessions = useMemo(() => {
    if (scope === 'all') return fullSessions || [];
    return applyDisplayFilter(sessions || [], filterState);
  }, [sessions, fullSessions, scope, filterState]);

  // Note state — persists per nodeId
  const existingNote = annotations.find(a => a.annotation_type === 'note' && a.node_id === nodeId);
  const [noteText, setNoteText] = useState(existingNote?.text || '');
  const [noteSaved, setNoteSaved] = useState(false);

  // Reset note text when the selected node changes
  useEffect(() => {
    const note = annotations.find(a => a.annotation_type === 'note' && a.node_id === nodeId);
    setNoteText(note?.text || '');
    setNoteSaved(false);
  }, [nodeId, annotations]);

  // Synthetic edit state
  const [synLabel, setSynLabel] = useState(node?.label || '');
  const [synIp, setSynIp]       = useState(node?.ip || '');
  const [synColor, setSynColor] = useState(node?.color || '#f0883e');
  const [synSaved, setSynSaved] = useState(false);

  const saveNote = useCallback(async () => {
    if (onSaveNote) {
      await onSaveNote(nodeId, noteText, existingNote?.id);
      setNoteSaved(true);
      setTimeout(() => setNoteSaved(false), 1500);
    }
  }, [nodeId, noteText, existingNote, onSaveNote]);

  const saveSynthetic = useCallback(async () => {
    if (onUpdateSynthetic) {
      await onUpdateSynthetic(nodeId, { label: synLabel, ip: synIp, color: synColor });
      setSynSaved(true);
      setTimeout(() => setSynSaved(false), 1500);
    }
  }, [nodeId, synLabel, synIp, synColor, onUpdateSynthetic]);

  if (!node) return null;

  const edgeSource = (scope === 'all' && fullEdges?.current) ? fullEdges.current : edges;
  const ce = edgeSource.filter(e => {
    const s = typeof e.source === 'object' ? e.source.id : e.source;
    const t = typeof e.target === 'object' ? e.target.id : e.target;
    return s === nodeId || t === nodeId;
  });

  const nodePluginResults = { ...pluginResults };

  // Slice os_fingerprint to this node
  const osFps = pluginResults?.os_fingerprint?.os_fingerprint || {};
  const osFp = osFps[nodeId] || (node.ips || []).reduce((a, ip) => a || osFps[ip], null);
  nodePluginResults.os_fingerprint = {
    ...pluginResults?.os_fingerprint,
    os_fingerprint: osFp || null,
  };

  // Slice network_role to this node — pick most informative role across all IPs
  const nrMap = pluginResults?.network_map?.network_role || {};
  const rolePriority = { gateway: 4, lan: 3, external: 2, unknown: 1 };
  const nodeNr = (node.ips || [nodeId]).reduce((best, ip) => {
    const r = nrMap[ip];
    if (!r) return best;
    if (!best || (rolePriority[r.role] || 0) > (rolePriority[best.role] || 0)) return r;
    return best;
  }, nrMap[nodeId] || null);
  nodePluginResults.network_map = {
    ...pluginResults?.network_map,
    network_role: nodeNr || null,
  };

  const dedicated = {
    'os_fingerprint.os_fingerprint': OSFingerprintNodeRenderer,
    'network_map.network_role':      NetworkRoleRenderer,
  };

  return (
    <div className="fi" style={{ padding: 16, overflowY: 'auto', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <div className="sh" style={{ marginBottom: 0 }}>Node Detail</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <ScopePill value={scope} onChange={setScope} />
          <button className="btn" onClick={onClear}>✕</button>
        </div>
      </div>

      <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4, wordBreak: 'break-all' }}>
        {node.synthetic ? (synLabel || node.id) : node.id}
      </div>

      {node.hostnames?.length > 0 && (
        <div style={{ marginBottom: 6 }}>
          {node.hostnames.map(h => (
            <div key={h} style={{ fontSize: 11, color: 'var(--acG)', lineHeight: 1.5 }}>{h}</div>
          ))}
        </div>
      )}

      {node.metadata?.name && !node.synthetic && (
        <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--ac)', marginBottom: 4 }}>
          {node.metadata.name}
          {node.metadata.role && <span style={{ color: 'var(--txM)', fontWeight: 400 }}> — {node.metadata.role}</span>}
        </div>
      )}

      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 10 }}>
        {node.synthetic && <Tag color="#f0883e">Synthetic</Tag>}
        {!node.synthetic && !node.is_subnet && <Tag color={node.is_private ? '#3fb950' : '#d29922'}>{node.is_private ? 'Private' : 'External'}</Tag>}
        {node.is_subnet && <Tag color="#bc8cff">Subnet</Tag>}
        {(node.protocols || []).map(p => <Tag key={p} color={pColors[p] || '#64748b'}>{p}</Tag>)}
      </div>

      {/* Synthetic node — editable fields */}
      {node.synthetic && (
        <div style={{ background: 'var(--bgC)', border: '1px solid var(--bd)', borderRadius: 6, padding: '10px 10px 8px', marginBottom: 10 }}>
          <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 8 }}>Edit node</div>
          <EditField label="Label" value={synLabel} onChange={setSynLabel} placeholder="Display name" />
          <EditField label="IP" value={synIp} onChange={setSynIp} placeholder="e.g. 10.0.0.1" />
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
            <span style={{ fontSize: 9, color: 'var(--txD)', width: 44, flexShrink: 0, textTransform: 'uppercase', letterSpacing: '.06em' }}>Color</span>
            <input type="color" value={synColor} onChange={e => setSynColor(e.target.value)}
              style={{ width: 32, height: 22, border: '1px solid var(--bd)', borderRadius: 3, background: 'none', cursor: 'pointer', padding: 1 }} />
            <span style={{ fontSize: 10, fontFamily: 'var(--fn)', color: 'var(--txD)' }}>{synColor}</span>
          </div>
          <button className="btn" onClick={saveSynthetic}
            style={{ fontSize: 9, padding: '2px 12px', width: '100%',
              background: synSaved ? 'rgba(63,185,80,.15)' : undefined,
              color: synSaved ? 'var(--acG)' : undefined,
              borderColor: synSaved ? 'var(--acG)' : undefined }}>
            {synSaved ? '✓ Saved' : 'Save'}
          </button>
        </div>
      )}

      {!node.synthetic && (
        <>
          <Row l="Packets" v={fN(node.packet_count)} />
          <Row l="Traffic volume" v={fB(node.total_bytes)} />
        </>
      )}

      {/* IPs */}
      {node.ips?.length > 0 && (
        <div style={{ marginBottom: 8, marginTop: 6 }}>
          <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 3 }}>IPs</div>
          {(node.ips || []).map(ip => {
            const addrType = classifyIp(ip);
            return (
              <div key={ip} style={{ fontSize: 10, fontFamily: 'var(--fn)', padding: '1px 0', color: 'var(--txM)', display: 'flex', alignItems: 'center', gap: 5 }}>
                <span>{ip}</span>
                {addrType && (
                  <span style={{
                    fontSize: 8, padding: '0px 5px', borderRadius: 8,
                    background: addrType.bg, color: addrType.fg,
                    fontFamily: 'var(--fn)', letterSpacing: '.03em', lineHeight: '15px',
                    whiteSpace: 'nowrap', flexShrink: 0,
                  }}>{addrType.label}</span>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* MACs with vendor inline */}
      {node.macs?.length > 0 && (
        <div style={{ marginBottom: 8 }}>
          <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 3 }}>MACs</div>
          {(node.macs || []).map((mac, i) => {
            const vendor = node.mac_vendors?.[i] || '';
            return (
              <div key={mac} style={{ fontSize: 10, fontFamily: 'var(--fn)', padding: '1px 0' }}>
                <span style={{ color: 'var(--txM)' }}>{mac}</span>
                {vendor && <span style={{ color: 'var(--txD)', marginLeft: 6 }}>({vendor})</span>}
              </div>
            );
          })}
        </div>
      )}

      {/* Advanced — TTLs only */}
      {(node.ttls_out?.length > 0 || node.ttls_in?.length > 0) && (
        <Collapse title="Advanced">
          {node.ttls_out?.length > 0 && <Row l="TTL outgoing" v={node.ttls_out.join(', ')} />}
          {node.ttls_in?.length > 0 && <Row l="TTL incoming" v={node.ttls_in.join(', ')} />}
        </Collapse>
      )}

      {/* Statistics — port distributions, top neighbors, protocols */}
      {!node.synthetic && <NodeStatistics node={node} onSelectNode={onSelectNode} />}

      {node.metadata && Object.keys(node.metadata).length > 0 && !node.synthetic && (
        <Collapse title="Researcher Metadata" open={true}>
          {Object.entries(node.metadata).map(([k, v]) => (
            <Row key={k} l={k} v={String(v)} />
          ))}
        </Collapse>
      )}

      {/* Plugin slots */}
      {!node.synthetic && (
        <PluginSections
          slotType="node_detail_section"
          pluginResults={nodePluginResults}
          uiSlots={uiSlots}
          dedicated={dedicated}
        />
      )}

      {/* Connections */}
      {(() => {
        const outgoing = [], incoming = [], both = [];
        for (const e of ce) {
          const s = typeof e.source === 'object' ? e.source.id : e.source;
          const t = typeof e.target === 'object' ? e.target.id : e.target;
          const other = s === nodeId ? t : s;

          const nodeIps = new Set(node.ips || [nodeId]);
          const edgeSess = displaySessions.filter(sess => {
            const sessIps = new Set([sess.src_ip, sess.dst_ip]);
            const nodeMatch = [...nodeIps].some(ip => sessIps.has(ip));
            return nodeMatch && sess.protocol === e.protocol;
          });

          let initCount = 0, respCount = 0;
          for (const sess of edgeSess) {
            if (nodeIps.has(sess.initiator_ip)) initCount++;
            else if (nodeIps.has(sess.responder_ip)) respCount++;
          }

          const dir = edgeSess.length === 0 ? 'both'
            : initCount > respCount ? 'out'
            : respCount > initCount ? 'in'
            : 'both';

          const row = (
            <div key={e.id || other} className="hr" onClick={() => onSelectEdge(e)}
              style={{
                fontSize: 10, padding: '4px 2px', borderBottom: '1px solid var(--bd)',
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                borderRadius: 3, cursor: 'pointer',
              }}>
              <span style={{ fontSize: 9, color: 'var(--txD)', flexShrink: 0, width: 12 }}>
                {dir === 'out' ? '→' : dir === 'in' ? '←' : '↔'}
              </span>
              <Tag color={pColors[e.protocol] || '#64748b'} small>{e.protocol}</Tag>
              <span style={{ color: 'var(--txM)', flex: 1, marginLeft: 6, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{other}</span>
              <span style={{ color: 'var(--txD)', marginLeft: 4 }}>{fB(e.total_bytes)}</span>
            </div>
          );
          if (dir === 'out') outgoing.push(row);
          else if (dir === 'in') incoming.push(row);
          else both.push(row);
        }

        const SectionLabel = ({ label, count }) => count === 0 ? null : (
          <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em',
            padding: '4px 2px 2px', marginTop: 4 }}>{label} ({count})</div>
        );

        return (
          <Collapse title={'Connections (' + ce.length + ')'} open={true}>
            <SectionLabel label="Outgoing" count={outgoing.length} />
            {outgoing}
            <SectionLabel label="Incoming" count={incoming.length} />
            {incoming}
            {both.length > 0 && <SectionLabel label="Both / Unknown" count={both.length} />}
            {both}
          </Collapse>
        );
      })()}

      {/* Notes — at the bottom so they don't interrupt the data flow */}
      <Collapse title="Notes" open={!!noteText}>
        <textarea
          value={noteText}
          onChange={e => setNoteText(e.target.value)}
          placeholder="Add investigation notes…"
          rows={3}
          style={{
            width: '100%', boxSizing: 'border-box',
            background: 'var(--bgC)', border: '1px solid var(--bd)', borderRadius: 4,
            padding: '6px 8px', fontSize: 10, color: 'var(--txM)',
            fontFamily: 'inherit', resize: 'vertical', outline: 'none',
            lineHeight: 1.5,
          }}
        />
        <button className="btn" onClick={saveNote}
          style={{ fontSize: 9, padding: '2px 12px', marginTop: 5, width: '100%',
            background: noteSaved ? 'rgba(63,185,80,.15)' : undefined,
            color: noteSaved ? 'var(--acG)' : undefined,
            borderColor: noteSaved ? 'var(--acG)' : undefined }}>
          {noteSaved ? '✓ Saved' : 'Save note'}
        </button>
      </Collapse>
    </div>
  );
}
