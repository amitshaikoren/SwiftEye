import React, { useState, useEffect, useCallback } from 'react';
import Tag from './Tag';
import Collapse from './Collapse';
import Row from './Row';
import { PluginSections, GenericDisplay } from './PluginSection';
import { fN, fB } from '../utils';

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

export default function NodeDetail({
  nodeId, nodes, edges, sessions, pColors, onClear, onSelectEdge, onSelectSession,
  pluginResults, uiSlots, annotations = [], onSaveNote, onUpdateSynthetic,
}) {
  const node = nodes.find(n => n.id === nodeId);

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

  const ce = edges.filter(e => {
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
        <button className="btn" onClick={onClear}>✕</button>
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
          {(node.ips || []).map(ip => (
            <div key={ip} style={{ fontSize: 10, fontFamily: 'var(--fn)', padding: '1px 0', color: 'var(--txM)' }}>{ip}</div>
          ))}
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
          const edgeSess = (sessions || []).filter(sess => {
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
