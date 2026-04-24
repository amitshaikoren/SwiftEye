/**
 * ClusterDetail — right panel content when a cluster or subnet node is selected.
 * Shows cluster summary, member list, protocol breakdown, connections, and notes.
 */

import React, { useState, useRef, useMemo, useCallback, useEffect } from 'react';
import Collapse from './Collapse';
import Row from './Row';
import { fN, fB } from '../utils';
import { CLUSTER_COLORS } from '../clusterView';

/** One row in the Connections section — shows the edge + optional bridge-node sub-list */
function BridgeEdgeRow({ e, other, bridges, pColors, onSelectEdge, onSelectNode }) {
  const [expanded, setExpanded] = useState(false);
  const hasBridges = bridges && bridges.length > 0;
  return (
    <div>
      <div
        style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '3px 5px', borderRadius: 3, fontSize: 10 }}
        onMouseEnter={el => el.currentTarget.style.background = 'var(--bgH)'}
        onMouseLeave={el => el.currentTarget.style.background = 'transparent'}
      >
        <span style={{ width: 10, height: 2.5, borderRadius: 1, flexShrink: 0, background: pColors?.[e.protocol] || '#64748b' }} />
        <span
          onClick={() => onSelectEdge?.(e)}
          style={{ flex: 1, color: 'var(--tx)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', cursor: 'pointer' }}
        >{other}</span>
        <span style={{ color: 'var(--txD)', fontSize: 9, flexShrink: 0 }}>{e.protocol}</span>
        <span style={{ color: 'var(--txD)', fontSize: 9, flexShrink: 0 }}>{fB(e.total_bytes || 0)}</span>
        {hasBridges && (
          <span
            onClick={() => setExpanded(x => !x)}
            title={`${bridges.length} bridge pair${bridges.length > 1 ? 's' : ''}`}
            style={{ fontSize: 9, color: 'var(--txD)', padding: '0 2px', cursor: 'pointer', flexShrink: 0 }}
          >{expanded ? '▼' : '▶'}</span>
        )}
      </div>
      {expanded && hasBridges && (
        <div style={{ padding: '2px 5px 4px 18px', display: 'flex', flexDirection: 'column', gap: 1 }}>
          {bridges.slice(0, 20).map((p, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9, color: 'var(--txM)' }}>
              <span onClick={() => onSelectNode?.(p.from)} style={{ cursor: 'pointer', color: 'var(--ac)' }}>{p.from}</span>
              <span style={{ color: 'var(--txD)' }}>→</span>
              <span onClick={() => onSelectNode?.(p.to)} style={{ cursor: 'pointer', color: 'var(--ac)' }}>{p.to}</span>
            </div>
          ))}
          {bridges.length > 20 && (
            <div style={{ fontSize: 9, color: 'var(--txD)' }}>+{bridges.length - 20} more pairs</div>
          )}
        </div>
      )}
    </div>
  );
}

/** Inline expandable detail for a single member node */
function MemberRow({ member, pColors, onNavigate }) {
  const [expanded, setExpanded] = useState(false);
  const m = member;
  const label = m.hostnames?.length > 0 ? m.hostnames[0] : m.id;
  const hasHostname = m.hostnames?.length > 0 && m.hostnames[0] !== m.id;

  return (
    <div>
      <div
        onClick={() => onNavigate?.(m.id)}
        title={`${m.id} — click to open detail`}
        style={{
          display: 'flex', alignItems: 'center', gap: 6, padding: '3px 5px',
          borderRadius: 3, cursor: 'pointer', fontSize: 10,
        }}
        onMouseEnter={e => e.currentTarget.style.background = 'var(--bgH)'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
      >
        <span style={{
          width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
          background: m.is_private ? 'var(--node-private)' : 'var(--node-external)',
          border: `1px solid ${m.is_private ? 'var(--node-private-s)' : 'var(--node-external-s)'}`,
        }} />
        <span style={{ flex: 1, color: 'var(--tx)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {label}
        </span>
        <span style={{ color: 'var(--txD)', fontSize: 9, flexShrink: 0 }}>
          {fB(m.total_bytes || 0)}
        </span>
        <span
          onClick={e => { e.stopPropagation(); setExpanded(!expanded); }}
          style={{ fontSize: 9, color: 'var(--txD)', padding: '0 2px', cursor: 'pointer' }}
        >{expanded ? '\u25BC' : '\u25B6'}</span>
      </div>
      {expanded && (
        <div style={{ padding: '2px 5px 4px 18px', fontSize: 9, color: 'var(--txM)', display: 'flex', flexDirection: 'column', gap: 2 }}>
          <Row l="IP" v={m.id} />
          {hasHostname && <Row l="Hostname" v={m.hostnames[0]} />}
          <Row l="Packets" v={fN(m.packet_count || 0)} />
          <Row l="Data" v={fB(m.total_bytes || 0)} />
          {m.protocols?.length > 0 && (
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 2 }}>
              {m.protocols.map(p => (
                <span key={p} style={{
                  fontSize: 9, padding: '0 4px', borderRadius: 2,
                  background: (pColors?.[p] || '#64748b') + '20',
                  color: pColors?.[p] || '#64748b',
                  border: `1px solid ${(pColors?.[p] || '#64748b') + '40'}`,
                }}>{p}</span>
              ))}
            </div>
          )}
          {m.macs?.length > 0 && <Row l="MACs" v={m.macs.join(', ')} />}
          {m.mac_vendors?.length > 0 && <Row l="Vendor" v={m.mac_vendors[0]} />}
        </div>
      )}
    </div>
  );
}

/** Editable cluster name in the detail header — click to rename */
function EditableClusterName({ isCluster, clusterId, displayName, onRename }) {
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState(displayName);
  const inputRef = useRef(null);

  useEffect(() => { setValue(displayName); }, [displayName]);
  useEffect(() => { if (editing) inputRef.current?.select(); }, [editing]);

  if (!isCluster) {
    return <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--tx)' }}>{displayName}</span>;
  }

  if (editing) {
    return (
      <input
        ref={inputRef}
        autoFocus
        value={value}
        onChange={e => setValue(e.target.value)}
        onBlur={() => { onRename?.(clusterId, value.trim() || displayName); setEditing(false); }}
        onKeyDown={e => {
          if (e.key === 'Enter') e.target.blur();
          if (e.key === 'Escape') { setValue(displayName); setEditing(false); }
        }}
        style={{
          fontWeight: 600, fontSize: 13, color: 'var(--tx)', background: 'var(--bgH)',
          border: '1px solid var(--bd)', borderRadius: 3, padding: '0 4px',
          outline: 'none', fontFamily: 'inherit', minWidth: 0, maxWidth: 160,
        }}
      />
    );
  }

  return (
    <span
      onClick={() => setEditing(true)}
      title="Click to rename"
      style={{
        fontWeight: 600, fontSize: 13, color: 'var(--tx)', cursor: 'text',
        borderBottom: '1px dashed var(--bd)', paddingBottom: 1,
      }}
    >
      {displayName}
    </span>
  );
}

export default function ClusterDetail({
  nodeId, nodes, edges, sessions, pColors,
  onClear, onSelectNode, onSelectEdge, onSelectSession,
  clusterNames, onRenameCluster, rawGraph,
  annotations = [], onSaveNote,
}) {
  const [memberSort, setMemberSort] = useState('bytes'); // 'bytes' | 'packets' | 'name'

  const node = useMemo(() => (nodes || []).find(n => n.id === nodeId), [nodes, nodeId]);

  // Determine if this is a cluster or subnet
  const isCluster = !!node?.is_cluster;
  const isSubnet = !!node?.is_subnet;

  // Resolve member nodes from rawGraph (the unclustered data)
  const members = useMemo(() => {
    if (!rawGraph?.nodes) return [];
    // For clusters: use member_ids
    if (node?.member_ids) {
      const idSet = new Set(node.member_ids);
      return rawGraph.nodes.filter(n => idSet.has(n.id));
    }
    // For subnets: member IPs are in node.ips
    if (isSubnet && node?.ips?.length > 0) {
      const ipSet = new Set(node.ips);
      return rawGraph.nodes.filter(n => ipSet.has(n.id));
    }
    return [];
  }, [node, rawGraph, isSubnet]);

  // Edges connected to this node
  const connectedEdges = useMemo(() => {
    if (!nodeId) return [];
    return (edges || []).filter(e => {
      const s = e.source?.id ?? e.source;
      const t = e.target?.id ?? e.target;
      return s === nodeId || t === nodeId;
    });
  }, [edges, nodeId]);

  // Sessions for member IPs
  const memberIps = useMemo(() => new Set(node?.ips || []), [node]);
  const clusterSessions = useMemo(() => {
    if (memberIps.size === 0) return [];
    return (sessions || []).filter(s =>
      memberIps.has(s.src_ip) || memberIps.has(s.dst_ip)
    );
  }, [sessions, memberIps]);

  // Protocol breakdown from members
  const protocolBreakdown = useMemo(() => {
    const map = {};
    for (const m of members) {
      for (const p of (m.protocols || [])) {
        if (!map[p]) map[p] = { count: 0, bytes: 0 };
        map[p].count++;
        map[p].bytes += m.total_bytes || 0;
      }
    }
    return Object.entries(map).sort((a, b) => b[1].bytes - a[1].bytes);
  }, [members]);

  // Bridge node pairs for each inter-cluster edge: which raw members cross to the other cluster?
  const bridgesByEdgeId = useMemo(() => {
    if (!rawGraph?.edges || !rawGraph?.nodes) return {};
    const myIds = new Set(node?.member_ids || node?.ips || []);
    if (myIds.size === 0) return {};
    const result = {};
    for (const ce of connectedEdges) {
      const src = ce.source?.id ?? ce.source;
      const tgt = ce.target?.id ?? ce.target;
      const otherId = src === nodeId ? tgt : src;
      const otherNode = (nodes || []).find(n => n.id === otherId);
      if (!otherNode) continue;
      const otherIds = new Set(otherNode.member_ids || otherNode.ips || []);
      if (otherIds.size === 0) continue;
      const pairs = [];
      for (const re of rawGraph.edges) {
        const rs = re.source?.id ?? re.source;
        const rt = re.target?.id ?? re.target;
        if (myIds.has(rs) && otherIds.has(rt)) pairs.push({ from: rs, to: rt });
        else if (myIds.has(rt) && otherIds.has(rs)) pairs.push({ from: rt, to: rs });
      }
      if (pairs.length > 0) result[ce.id ?? `${src}|${tgt}`] = pairs;
    }
    return result;
  }, [rawGraph, node, nodes, connectedEdges, nodeId]);

  // Split connected edges into bridge edges (other is a cluster) vs external (other is a regular/subnet node)
  const { bridgeEdges, externalConnEdges } = useMemo(() => {
    const bridges = [], external = [];
    for (const e of connectedEdges) {
      const src = e.source?.id ?? e.source;
      const tgt = e.target?.id ?? e.target;
      const otherId = src === nodeId ? tgt : src;
      const otherNode = (nodes || []).find(n => n.id === otherId);
      if (otherNode?.is_cluster) bridges.push(e);
      else external.push(e);
    }
    return { bridgeEdges: bridges, externalConnEdges: external };
  }, [connectedEdges, nodes, nodeId]);

  // Internal raw edges (both endpoints inside this cluster)
  const internalRawEdges = useMemo(() => {
    if (!rawGraph?.edges) return [];
    const myIds = new Set(node?.member_ids || node?.ips || []);
    if (myIds.size === 0) return [];
    return rawGraph.edges.filter(e => {
      const s = e.source?.id ?? e.source;
      const t = e.target?.id ?? e.target;
      return myIds.has(s) && myIds.has(t);
    });
  }, [rawGraph, node]);

  // Partition cluster sessions into internal (both sides in cluster) and external
  const { internalSessions, externalSessions } = useMemo(() => {
    const internal = [], external = [];
    for (const s of clusterSessions) {
      if (memberIps.has(s.src_ip) && memberIps.has(s.dst_ip)) internal.push(s);
      else external.push(s);
    }
    return { internalSessions: internal, externalSessions: external };
  }, [clusterSessions, memberIps]);

  // Per-endpoint-pair internal session count for internal edge rows
  const internalSessionPairCounts = useMemo(() => {
    const map = {};
    for (const s of internalSessions) {
      const k = `${s.src_ip}|${s.dst_ip}`;
      map[k] = (map[k] || 0) + 1;
    }
    return map;
  }, [internalSessions]);

  // Per-other-node external session count for external connection rows
  const externalSessionsByOtherId = useMemo(() => {
    const map = {};
    for (const s of externalSessions) {
      const otherId = memberIps.has(s.src_ip) ? s.dst_ip : s.src_ip;
      map[otherId] = (map[otherId] || 0) + 1;
    }
    return map;
  }, [externalSessions, memberIps]);

  // Sort members
  const sortedMembers = useMemo(() => {
    const sorted = [...members];
    if (memberSort === 'bytes') sorted.sort((a, b) => (b.total_bytes || 0) - (a.total_bytes || 0));
    else if (memberSort === 'packets') sorted.sort((a, b) => (b.packet_count || 0) - (a.packet_count || 0));
    else sorted.sort((a, b) => (a.id || '').localeCompare(b.id || ''));
    return sorted;
  }, [members, memberSort]);

  // Notes
  const existingNote = annotations.find(a => a.annotation_type === 'note' && a.node_id === nodeId);
  const [noteText, setNoteText] = useState(existingNote?.text || '');
  const [noteSaved, setNoteSaved] = useState(false);

  useEffect(() => {
    const note = annotations.find(a => a.annotation_type === 'note' && a.node_id === nodeId);
    setNoteText(note?.text || '');
    setNoteSaved(false);
  }, [nodeId, annotations]);

  const saveNote = useCallback(async () => {
    if (onSaveNote) {
      await onSaveNote(nodeId, noteText, existingNote?.id);
      setNoteSaved(true);
      setTimeout(() => setNoteSaved(false), 1500);
    }
  }, [nodeId, noteText, existingNote, onSaveNote]);

  if (!node) return null;

  const memberCount = node.member_count || node.ips?.length || 0;
  const cid = node.cluster_id ?? 0;
  const color = isCluster ? CLUSTER_COLORS[cid % CLUSTER_COLORS.length] : 'var(--node-subnet-s)';

  // Display name: custom name for clusters, subnet ID for subnets
  const displayName = isCluster
    ? (clusterNames?.[cid] || `Cluster ${cid}`)
    : node.id;
  const typeLabel = isCluster ? 'cluster' : 'subnet';

  return (
    <div style={{ padding: '10px 12px', overflowY: 'auto', height: '100%', fontSize: 11 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {isCluster ? (
            <svg width={18} height={18}>
              <polygon
                points={Array.from({ length: 6 }, (_, i) => {
                  const a = (Math.PI / 3) * i - Math.PI / 6;
                  return `${9 + 8 * Math.cos(a)},${9 + 8 * Math.sin(a)}`;
                }).join(' ')}
                fill={color + '30'} stroke={color} strokeWidth={2}
              />
            </svg>
          ) : (
            <span style={{
              width: 14, height: 14, borderRadius: 2, display: 'inline-block',
              background: 'var(--node-subnet)', border: '1.5px solid var(--node-subnet-s)',
            }} />
          )}
          <EditableClusterName
            isCluster={isCluster}
            clusterId={cid}
            displayName={displayName}
            onRename={onRenameCluster}
          />
          <span style={{ fontSize: 9, color: typeLabel === 'cluster' ? '#bc8cff' : 'var(--txD)',
            border: `1px solid ${typeLabel === 'cluster' ? '#bc8cff' : 'var(--bd)'}`,
            borderRadius: 3, padding: '0 3px' }}>{typeLabel}</span>
        </div>
        <button onClick={onClear} style={{
          background: 'none', border: '1px solid var(--bd)', borderRadius: 4,
          color: 'var(--txD)', fontSize: 9, padding: '2px 6px', cursor: 'pointer',
        }}>&times;</button>
      </div>

      {/* Summary cards */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 6, marginBottom: 10 }}>
        {[
          { label: 'Members', value: fN(memberCount) },
          { label: 'Data', value: fB(node.total_bytes || 0) },
          { label: 'Packets', value: fN(node.packet_count || 0) },
        ].map(({ label, value }) => (
          <div key={label} style={{
            background: 'var(--bgH)', borderRadius: 4, padding: '6px 8px', textAlign: 'center',
          }}>
            <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--tx)' }}>{value}</div>
            <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: 0.5 }}>{label}</div>
          </div>
        ))}
      </div>


      {/* Protocol breakdown */}
      {protocolBreakdown.length > 0 && (
        <Collapse title="Protocols" defaultOpen>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            {protocolBreakdown.map(([proto, info]) => (
              <div key={proto} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{
                  width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                  background: pColors?.[proto] || '#64748b',
                }} />
                <span style={{ flex: 1, color: 'var(--tx)', fontSize: 10 }}>{proto}</span>
                <span style={{ color: 'var(--txD)', fontSize: 9 }}>{info.count} nodes</span>
                <span style={{ color: 'var(--txD)', fontSize: 9 }}>{fB(info.bytes)}</span>
              </div>
            ))}
          </div>
        </Collapse>
      )}

      {/* Member list — click to expand inline detail */}
      {members.length > 0 && (
        <Collapse title={`Members (${memberCount})`} defaultOpen>
          <div style={{ display: 'flex', gap: 4, marginBottom: 6 }}>
            {['bytes', 'packets', 'name'].map(s => (
              <button key={s} onClick={() => setMemberSort(s)} style={{
                fontSize: 9, padding: '1px 5px', cursor: 'pointer',
                background: memberSort === s ? 'var(--acB)' : 'transparent',
                color: memberSort === s ? '#fff' : 'var(--txD)',
                border: '1px solid var(--bd)', borderRadius: 3,
              }}>{s}</button>
            ))}
          </div>
          <div style={{ maxHeight: 250, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 1 }}>
            {sortedMembers.map(m => (
              <MemberRow key={m.id} member={m} pColors={pColors} onNavigate={onSelectNode} />
            ))}
          </div>
        </Collapse>
      )}

      {/* Bridges — cluster-to-cluster edges */}
      {bridgeEdges.length > 0 && (
        <Collapse title={`Bridges (${bridgeEdges.length})`} defaultOpen>
          <div style={{ maxHeight: 200, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 1 }}>
            {bridgeEdges
              .sort((a, b) => (b.total_bytes || 0) - (a.total_bytes || 0))
              .map(e => {
                const src = e.source?.id ?? e.source;
                const tgt = e.target?.id ?? e.target;
                const other = src === nodeId ? tgt : src;
                const edgeKey = e.id ?? `${src}|${tgt}`;
                return (
                  <BridgeEdgeRow
                    key={edgeKey}
                    e={e}
                    other={other}
                    bridges={bridgesByEdgeId[edgeKey]}
                    pColors={pColors}
                    onSelectEdge={onSelectEdge}
                    onSelectNode={onSelectNode}
                  />
                );
              })}
          </div>
        </Collapse>
      )}

      {/* Internal edges — within this cluster's members */}
      {internalRawEdges.length > 0 && (
        <Collapse title={`Internal Edges (${internalRawEdges.length} · ${internalSessions.length} sessions)`}>
          <div style={{ maxHeight: 200, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 1 }}>
            {internalRawEdges
              .sort((a, b) => (b.total_bytes || 0) - (a.total_bytes || 0))
              .slice(0, 50)
              .map((e, i) => {
                const src = e.source?.id ?? e.source;
                const tgt = e.target?.id ?? e.target;
                const sessions = internalSessionPairCounts[`${src}|${tgt}`]
                  || internalSessionPairCounts[`${tgt}|${src}`] || 0;
                return (
                  <div key={i} style={{
                    display: 'flex', alignItems: 'center', gap: 6,
                    padding: '3px 5px', borderRadius: 3, fontSize: 10,
                  }}
                    onMouseEnter={el => el.currentTarget.style.background = 'var(--bgH)'}
                    onMouseLeave={el => el.currentTarget.style.background = 'transparent'}
                  >
                    <span style={{
                      width: 10, height: 2.5, borderRadius: 1, flexShrink: 0,
                      background: pColors?.[e.protocol] || '#64748b',
                    }} />
                    <span
                      onClick={() => onSelectNode?.(src)}
                      style={{ color: 'var(--ac)', cursor: 'pointer', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 90 }}
                    >{src}</span>
                    <span style={{ color: 'var(--txD)', fontSize: 9 }}>→</span>
                    <span
                      onClick={() => onSelectNode?.(tgt)}
                      style={{ color: 'var(--ac)', cursor: 'pointer', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 90 }}
                    >{tgt}</span>
                    <span style={{ flex: 1 }} />
                    {sessions > 0 && (
                      <span style={{ color: 'var(--txD)', fontSize: 9, flexShrink: 0 }}>{sessions}s</span>
                    )}
                    <span style={{ color: 'var(--txD)', fontSize: 9, flexShrink: 0 }}>{fB(e.total_bytes || 0)}</span>
                  </div>
                );
              })}
            {internalRawEdges.length > 50 && (
              <div style={{ fontSize: 9, color: 'var(--txD)', padding: '2px 5px' }}>+{internalRawEdges.length - 50} more</div>
            )}
          </div>
        </Collapse>
      )}

      {/* External connections — cluster members to outside nodes */}
      {externalConnEdges.length > 0 && (
        <Collapse title={`External Connections (${externalConnEdges.length} · ${externalSessions.length} sessions)`} defaultOpen>
          <div style={{ maxHeight: 200, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 1 }}>
            {externalConnEdges
              .sort((a, b) => (b.total_bytes || 0) - (a.total_bytes || 0))
              .map(e => {
                const src = e.source?.id ?? e.source;
                const tgt = e.target?.id ?? e.target;
                const otherId = src === nodeId ? tgt : src;
                const edgeKey = e.id ?? `${src}|${tgt}`;
                const sessionCount = externalSessionsByOtherId[otherId] || 0;
                return (
                  <div key={edgeKey} style={{
                    display: 'flex', alignItems: 'center', gap: 6,
                    padding: '3px 5px', borderRadius: 3, fontSize: 10,
                  }}
                    onMouseEnter={el => el.currentTarget.style.background = 'var(--bgH)'}
                    onMouseLeave={el => el.currentTarget.style.background = 'transparent'}
                  >
                    <span style={{
                      width: 10, height: 2.5, borderRadius: 1, flexShrink: 0,
                      background: pColors?.[e.protocol] || '#64748b',
                    }} />
                    <span
                      onClick={() => onSelectEdge?.(e)}
                      style={{ flex: 1, color: 'var(--tx)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', cursor: 'pointer' }}
                    >{otherId}</span>
                    <span style={{ color: 'var(--txD)', fontSize: 9, flexShrink: 0 }}>{e.protocol}</span>
                    {sessionCount > 0 && (
                      <span style={{ color: 'var(--txD)', fontSize: 9, flexShrink: 0 }}>{sessionCount}s</span>
                    )}
                    <span style={{ color: 'var(--txD)', fontSize: 9, flexShrink: 0 }}>{fB(e.total_bytes || 0)}</span>
                  </div>
                );
              })}
          </div>
        </Collapse>
      )}

      {/* Sessions */}
      {clusterSessions.length > 0 && (
        <Collapse title={`Sessions (${clusterSessions.length})`}>
          <div style={{ maxHeight: 200, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 1 }}>
            {clusterSessions.slice(0, 50).map(s => (
              <div
                key={s.session_id}
                onClick={() => onSelectSession?.(s)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6, padding: '3px 5px',
                  borderRadius: 3, cursor: 'pointer', fontSize: 10,
                }}
                onMouseEnter={e => e.currentTarget.style.background = 'var(--bgH)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              >
                <span style={{
                  width: 10, height: 2.5, borderRadius: 1, flexShrink: 0,
                  background: pColors?.[s.protocol] || '#64748b',
                }} />
                <span style={{ color: 'var(--txM)', fontSize: 9, flexShrink: 0 }}>{s.src_ip}</span>
                <span style={{ color: 'var(--txD)', fontSize: 9 }}>{'\u2194'}</span>
                <span style={{ color: 'var(--txM)', fontSize: 9, flexShrink: 0 }}>{s.dst_ip}</span>
                <span style={{ flex: 1 }} />
                <span style={{ color: 'var(--txD)', fontSize: 9 }}>{fB(s.total_bytes || 0)}</span>
              </div>
            ))}
            {clusterSessions.length > 50 && (
              <div style={{ fontSize: 9, color: 'var(--txD)', padding: '2px 5px' }}>
                +{clusterSessions.length - 50} more
              </div>
            )}
          </div>
        </Collapse>
      )}

      {/* Notes */}
      <Collapse title="Notes" open={!!noteText}>
        <textarea
          value={noteText}
          onChange={e => setNoteText(e.target.value)}
          placeholder="Add investigation notes..."
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
          {noteSaved ? '\u2713 Saved' : 'Save note'}
        </button>
      </Collapse>
    </div>
  );
}
