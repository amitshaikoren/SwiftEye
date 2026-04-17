import React, { useMemo } from 'react';
import Tag from './Tag';
import Collapse from './Collapse';
import Row from './Row';
import { fN, fB, fD, fT } from '../utils';

/**
 * Panel shown when 2+ nodes are selected (shift+click).
 * Computes scoped statistics from the already-loaded graph and session data.
 */
export default function MultiSelectPanel({
  selectedNodes, nodes, edges, sessions, pColors, onClear, onSelectNode, onSelectEdge, onSelectSession,
  onAnimate,
}) {
  const selSet = useMemo(() => new Set(selectedNodes), [selectedNodes]);

  // Nodes in selection
  const selNodeData = useMemo(
    () => nodes.filter(n => selSet.has(n.id)),
    [nodes, selSet]
  );

  // All IPs belonging to selected nodes (for session matching)
  const selIps = useMemo(() => {
    const ips = new Set();
    for (const n of selNodeData) {
      ips.add(n.id);
      for (const ip of (n.ips || [])) ips.add(ip);
    }
    return ips;
  }, [selNodeData]);

  // Edges between selected nodes
  const selEdges = useMemo(
    () => edges.filter(e => {
      const s = typeof e.source === 'object' ? e.source.id : e.source;
      const t = typeof e.target === 'object' ? e.target.id : e.target;
      return selSet.has(s) && selSet.has(t);
    }),
    [edges, selSet]
  );

  // Edges connected to selected nodes (including external)
  const connEdges = useMemo(
    () => edges.filter(e => {
      const s = typeof e.source === 'object' ? e.source.id : e.source;
      const t = typeof e.target === 'object' ? e.target.id : e.target;
      return selSet.has(s) || selSet.has(t);
    }),
    [edges, selSet]
  );

  // Sessions involving selected nodes
  const selSessions = useMemo(
    () => sessions.filter(s => selIps.has(s.src_ip) || selIps.has(s.dst_ip) ||
      selIps.has(s.initiator_ip) || selIps.has(s.responder_ip)),
    [sessions, selIps]
  );

  // Sessions exclusively between selected nodes
  const internalSessions = useMemo(
    () => sessions.filter(s =>
      (selIps.has(s.src_ip) || selIps.has(s.initiator_ip)) &&
      (selIps.has(s.dst_ip) || selIps.has(s.responder_ip))
    ),
    [sessions, selIps]
  );

  // Aggregate stats
  const stats = useMemo(() => {
    const totalPackets = selNodeData.reduce((a, n) => a + n.packet_count, 0);
    const totalBytes = selNodeData.reduce((a, n) => a + n.total_bytes, 0);
    const allIps = new Set();
    const allMacs = new Set();
    const protoCounts = {};

    for (const n of selNodeData) {
      for (const ip of (n.ips || [])) allIps.add(ip);
      for (const mac of (n.macs || [])) allMacs.add(mac);
      for (const p of (n.protocols || [])) {
        protoCounts[p] = (protoCounts[p] || 0) + 1;
      }
    }

    // Edge-based stats (traffic between these nodes)
    const internalBytes = selEdges.reduce((a, e) => a + e.total_bytes, 0);
    const internalPackets = selEdges.reduce((a, e) => a + e.packet_count, 0);

    // Protocol breakdown from connected edges
    const protoTraffic = {};
    for (const e of connEdges) {
      if (!protoTraffic[e.protocol]) protoTraffic[e.protocol] = { packets: 0, bytes: 0 };
      protoTraffic[e.protocol].packets += e.packet_count;
      protoTraffic[e.protocol].bytes += e.total_bytes;
    }

    // Session stats
    let hsCount = 0, rstCount = 0, finCount = 0;
    let totalSessionBytes = 0;
    for (const s of selSessions) {
      if (s.has_handshake) hsCount++;
      if (s.has_reset) rstCount++;
      if (s.has_fin) finCount++;
      totalSessionBytes += s.total_bytes;
    }

    return {
      totalPackets, totalBytes, allIps, allMacs, protoCounts,
      internalBytes, internalPackets, protoTraffic,
      hsCount, rstCount, finCount, totalSessionBytes,
    };
  }, [selNodeData, selEdges, connEdges, selSessions]);

  return (
    <div className="fi" style={{ padding: 16, overflowY: 'auto', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <div className="sh" style={{ marginBottom: 0 }}>
          Selection ({selectedNodes.length} nodes)
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {onAnimate && (
            <button
              className="btn"
              onClick={() => onAnimate(selectedNodes)}
              style={{
                background: 'rgba(88,166,255,.08)', borderColor: 'rgba(88,166,255,.28)',
                color: '#6ab4ff', fontSize: 10, padding: '3px 10px',
              }}
              title="Animate session timeline for selected nodes"
            >
              ▶ Animate
            </button>
          )}
          <button className="btn" onClick={onClear}>✕</button>
        </div>
      </div>

      {/* Summary grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginBottom: 16 }}>
        <div className="sc">
          <div style={{ fontSize: 9, color: 'var(--txM)', textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 2 }}>Nodes</div>
          <div style={{ fontSize: 17, fontWeight: 600, fontFamily: 'var(--fd)' }}>{selectedNodes.length}</div>
          <div style={{ fontSize: 9, color: 'var(--txD)' }}>{stats.allIps.size} IPs · {stats.allMacs.size} MACs</div>
        </div>
        <div className="sc">
          <div style={{ fontSize: 9, color: 'var(--txM)', textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 2 }}>Sessions</div>
          <div style={{ fontSize: 17, fontWeight: 600, fontFamily: 'var(--fd)' }}>{fN(selSessions.length)}</div>
          <div style={{ fontSize: 9, color: 'var(--txD)' }}>{fN(internalSessions.length)} internal</div>
        </div>
        <div className="sc">
          <div style={{ fontSize: 9, color: 'var(--txM)', textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 2 }}>Edges</div>
          <div style={{ fontSize: 17, fontWeight: 600, fontFamily: 'var(--fd)' }}>{connEdges.length}</div>
          <div style={{ fontSize: 9, color: 'var(--txD)' }}>{selEdges.length} between selected</div>
        </div>
        <div className="sc">
          <div style={{ fontSize: 9, color: 'var(--txM)', textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 2 }}>Traffic</div>
          <div style={{ fontSize: 17, fontWeight: 600, fontFamily: 'var(--fd)' }}>{fB(stats.totalBytes)}</div>
          <div style={{ fontSize: 9, color: 'var(--txD)' }}>{fB(stats.internalBytes)} internal</div>
        </div>
      </div>

      {/* TCP state */}
      {(stats.hsCount > 0 || stats.rstCount > 0 || stats.finCount > 0) && (
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
          {stats.hsCount > 0 && <Tag color="#3fb950">HS: {stats.hsCount}</Tag>}
          {stats.finCount > 0 && <Tag color="#d29922">FIN: {stats.finCount}</Tag>}
          {stats.rstCount > 0 && <Tag color="#f85149">RST: {stats.rstCount}</Tag>}
        </div>
      )}

      {/* Selected nodes list */}
      <Collapse title="Selected Nodes" open={true}>
        {selNodeData.map(n => (
          <div key={n.id} className="hr" onClick={() => onSelectNode(n.id)}
            style={{
              fontSize: 10, padding: '5px 4px', borderBottom: '1px solid var(--bd)',
              cursor: 'pointer', borderRadius: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            }}>
            <span style={{ fontWeight: 500 }}>{n.id}</span>
            <span style={{ color: 'var(--txD)' }}>{fB(n.total_bytes)}</span>
          </div>
        ))}
      </Collapse>

      {/* Protocol breakdown */}
      <Collapse title="Protocols" open={true}>
        {Object.entries(stats.protoTraffic)
          .sort((a, b) => b[1].bytes - a[1].bytes)
          .map(([proto, d]) => (
            <div key={proto} style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              fontSize: 10, padding: '3px 0', borderBottom: '1px solid var(--bd)',
            }}>
              <Tag color={pColors[proto] || '#64748b'} small>{proto}</Tag>
              <span style={{ color: 'var(--txM)' }}>{fN(d.packets)} pkts · {fB(d.bytes)}</span>
            </div>
          ))}
      </Collapse>

      {/* Internal edges */}
      {selEdges.length > 0 && (
        <Collapse title={`Edges Between Selected (${selEdges.length})`}>
          {selEdges.slice(0, 20).map((e, i) => {
            const s = typeof e.source === 'object' ? e.source.id : e.source;
            const t = typeof e.target === 'object' ? e.target.id : e.target;
            return (
              <div key={i} className="hr" onClick={() => onSelectEdge(e)}
                style={{
                  fontSize: 10, padding: '4px 2px', borderBottom: '1px solid var(--bd)',
                  cursor: 'pointer', borderRadius: 3,
                }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Tag color={pColors[e.protocol] || '#64748b'} small>{e.protocol}</Tag>
                  <span style={{ color: 'var(--txM)', flex: 1, marginLeft: 6, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {s} ↔ {t}
                  </span>
                  <span style={{ color: 'var(--txD)', marginLeft: 4 }}>{fB(e.total_bytes)}</span>
                </div>
              </div>
            );
          })}
        </Collapse>
      )}

      {/* Sessions */}
      <Collapse title={`Sessions (${selSessions.length})`}>
        {selSessions.slice(0, 30).map((s, i) => (
          <div key={i} className="hr" onClick={() => onSelectSession(s)}
            style={{
              padding: '5px 4px', borderBottom: '1px solid var(--bd)',
              cursor: 'pointer', borderRadius: 3,
            }}>
            <div style={{ fontSize: 10, fontWeight: 500 }}>
              {s.initiator_ip || s.src_ip}:{s.initiator_port || s.src_port} → {s.responder_ip || s.dst_ip}:{s.responder_port || s.dst_port}
            </div>
            <div style={{ display: 'flex', gap: 4, marginTop: 2, alignItems: 'center', flexWrap: 'wrap' }}>
              <Tag color={pColors[s.protocol] || '#64748b'} small>{s.protocol}</Tag>
              <span style={{ fontSize: 9, color: 'var(--txM)' }}>{fB(s.total_bytes)}</span>
              {s.has_handshake && <Tag color="#3fb950" small>HS</Tag>}
              {s.has_reset && <Tag color="#f85149" small>RST</Tag>}
              {s.has_fin && <Tag color="#d29922" small>FIN</Tag>}
            </div>
          </div>
        ))}
        {selSessions.length > 30 && (
          <div style={{ fontSize: 9, color: 'var(--txD)', padding: '4px 0' }}>
            +{selSessions.length - 30} more
          </div>
        )}
      </Collapse>
    </div>
  );
}
