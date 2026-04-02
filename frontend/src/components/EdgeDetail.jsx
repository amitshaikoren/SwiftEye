import React, { useMemo, useState, useEffect, useCallback } from 'react';
import Tag from './Tag';
import Collapse from './Collapse';
import Row from './Row';
import { fN, fB, fD, fT } from '../utils';
import { fetchSessions } from '../api';
import ScopePill from './ScopePill';
import { useFilterContext, applyDisplayFilter } from '../FilterContext';

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

// Renders a JA3 hash with inline app name when known
function JA3Badge({ hash, apps = [] }) {
  const app = apps.find(a => a.hash === hash);
  return (
    <div style={{ padding: '2px 0', display: 'flex', alignItems: 'baseline', gap: 6, flexWrap: 'wrap' }}>
      <span style={{ fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--ac)', wordBreak: 'break-all' }}>{hash}</span>
      {app && (
        <span style={{
          fontSize: 9, padding: '0 5px', borderRadius: 6, flexShrink: 0,
          background: app.is_malware ? 'rgba(248,81,73,.15)' : 'rgba(63,185,80,.08)',
          color: app.is_malware ? 'var(--acR)' : 'var(--acG)',
          border: '1px solid ' + (app.is_malware ? 'rgba(248,81,73,.3)' : 'rgba(63,185,80,.2)'),
          fontFamily: 'var(--fn)',
        }}>
          {app.is_malware ? '⚠ ' : ''}{app.name}
        </span>
      )}
    </div>
  );
}

export default function EdgeDetail({ edge: e, pColors, onClear, sessions, nodes = [], onSelectSession, annotations = [], onSaveNote, clusterNames, fullSessions }) {
  const filterCtx = useFilterContext();
  const [scope, setScope] = useScopeState('swifteye_scope_edge');
  const displaySessions = useMemo(() => {
    if (scope === 'all') return fullSessions || [];
    return applyDisplayFilter(sessions || [], filterCtx);
  }, [sessions, fullSessions, scope, filterCtx]);
  const src = e ? (typeof e.source === 'object' ? e.source.id : e.source) : '';
  const tgt = e ? (typeof e.target === 'object' ? e.target.id : e.target) : '';

  // Resolve cluster node IDs to display names
  const resolveDisplay = (id) => {
    if (!id.startsWith('cluster:')) return id;
    const n = nodes.find(nd => nd.id === id);
    const cid = n?.cluster_id;
    if (clusterNames?.[cid]) return clusterNames[cid];
    if (n?.member_count) return `Cluster ${cid} (${n.member_count} nodes)`;
    return id;
  };
  const srcDisplay = resolveDisplay(src);
  const tgtDisplay = resolveDisplay(tgt);
  const edgeId = e?.id || '';

  // Notes
  const [noteText, setNoteText] = useState('');
  const [noteSaved, setNoteSaved] = useState(false);
  const existingNote = annotations.find(a => a.annotation_type === 'note' && a.edge_id === edgeId);
  useEffect(() => { setNoteText(existingNote?.text || ''); setNoteSaved(false); }, [edgeId, annotations]);
  const saveNote = useCallback(async () => {
    if (onSaveNote) {
      await onSaveNote(edgeId, noteText, existingNote?.id, 'edge_id');
      setNoteSaved(true);
      setTimeout(() => setNoteSaved(false), 1500);
    }
  }, [edgeId, noteText, existingNote, onSaveNote]);

  const EDGE_SESSION_PAGE = 20;
  const [fetchedSessions, setFetchedSessions] = useState([]);
  const [loadingMore, setLoadingMore] = useState(false);
  const [expanded, setExpanded] = useState(false);
  // Reset state when edge changes
  useEffect(() => { setFetchedSessions([]); setExpanded(false); }, [src, tgt, e?.protocol]);

  const nodeIpsMap = useMemo(() => {
    const m = new Map();
    for (const n of nodes) {
      const allIps = new Set(n.ips || [n.id]);
      allIps.add(n.id);
      m.set(n.id, allIps);
    }
    return m;
  }, [nodes]);

  const edgeFilter = useCallback((list) => {
    if (!e) return [];
    function ipInCidr(ip, cidr) {
      if (!cidr.includes('/')) return ip === cidr;
      try {
        const [base, bits] = cidr.split('/');
        const mask = ~((1 << (32 - parseInt(bits, 10))) - 1) >>> 0;
        function toInt(s) {
          return s.split('.').reduce((a, b) => (a << 8) | parseInt(b, 10), 0) >>> 0;
        }
        return (toInt(ip) & mask) === (toInt(base) & mask);
      } catch { return false; }
    }
    function matchEndpoint(sessionIp, endpoint) {
      if (endpoint.includes('/')) return ipInCidr(sessionIp, endpoint);
      const nodeIps = nodeIpsMap.get(endpoint);
      if (nodeIps) return nodeIps.has(sessionIp);
      return sessionIp === endpoint;
    }
    return list.filter(s =>
      s.protocol === e.protocol &&
      ((matchEndpoint(s.src_ip, src) || matchEndpoint(s.dst_ip, src)) &&
       (matchEndpoint(s.src_ip, tgt) || matchEndpoint(s.dst_ip, tgt)))
    );
  }, [e, src, tgt, e?.protocol, nodeIpsMap]);

  // Initial edge sessions: filter from display-filtered list (cheap, no extra fetch)
  const edgeSessions = useMemo(() => {
    const fromGlobal = edgeFilter(displaySessions);
    if (fetchedSessions.length === 0) return fromGlobal;
    // Merge fetched with global, dedup by id
    const seen = new Set(fromGlobal.map(s => s.id));
    const merged = [...fromGlobal];
    for (const s of edgeFilter(fetchedSessions)) {
      if (!seen.has(s.id)) { seen.add(s.id); merged.push(s); }
    }
    return merged;
  }, [displaySessions, fetchedSessions, edgeFilter]);

  // Resolve a node ID to a real searchable IP (handles cluster IDs, MAC-split IDs)
  const resolveSearchIp = useCallback((id) => {
    if (!id || id.includes('/')) return ''; // subnet CIDR, can't search directly
    // MAC-split node IDs: "192.168.1.1::aa:bb:cc:dd:ee:ff" → strip the MAC
    if (id.includes('::')) return id.split('::')[0];
    if (!id.startsWith('cluster:')) return id;
    // For clusters, use the first member IP
    const n = nodes.find(nd => nd.id === id);
    if (n?.ips?.length > 0) return n.ips[0];
    return '';
  }, [nodes]);

  // "Show more" fetches sessions from the API using one of the edge IPs
  const loadMoreSessions = useCallback(() => {
    const searchIp = resolveSearchIp(src) || resolveSearchIp(tgt);
    if (!searchIp) return;
    setLoadingMore(true);
    fetchSessions(5000, searchIp)
      .then(d => setFetchedSessions(d.sessions || []))
      .catch(() => {})
      .finally(() => setLoadingMore(false));
  }, [src, tgt, resolveSearchIp]);

  if (!e) return null;

  const hasTLS = e.tls_snis?.length > 0 || e.tls_versions?.length > 0 || e.tls_ciphers?.length > 0 || e.ja3_hashes?.length > 0 || e.ja4_hashes?.length > 0;
  const hasDNS = e.dns_queries?.length > 0;
  const hasHTTP = e.http_hosts?.length > 0;

  return (
    <div className="fi" style={{ padding: 16, overflowY: 'auto', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <div className="sh" style={{ marginBottom: 0 }}>Edge Detail</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <ScopePill value={scope} onChange={setScope} />
          <button className="btn" onClick={onClear}>✕</button>
        </div>
      </div>

      <Tag color={pColors[e.protocol] || '#64748b'}>{e.protocol}</Tag>

      {e.protocol_conflict && (
        <div style={{
          marginTop: 6, padding: '6px 10px', background: 'rgba(248,81,73,.08)',
          border: '1px solid rgba(248,81,73,.25)', borderRadius: 'var(--rs)', fontSize: 10,
        }}>
          <span style={{ color: 'var(--acR)', fontWeight: 600 }}>⚠ Protocol conflict</span>
          <div style={{ color: 'var(--txM)', marginTop: 2 }}>
            Port says: {(e.protocol_by_port || []).join(', ') || 'unknown'}
            <br />
            Payload says: {(e.protocol_by_payload || []).join(', ') || 'unknown'}
          </div>
        </div>
      )}

      <div style={{ marginTop: 10 }}>
        <Row l="Source" v={srcDisplay} />
        <Row l="Target" v={tgtDisplay} />
        <Row l="Packets" v={fN(e.packet_count)} />
        <Row l="Traffic volume" v={fB(e.total_bytes)} />
        {e.first_seen && <Row l="Time range" v={fT(e.first_seen) + ' — ' + fT(e.last_seen)} />}
        {e.ports?.length > 0 && <Row l="Ports" v={e.ports.slice(0, 10).join(', ') + (e.ports.length > 10 ? '…' : '')} />}
      </div>

      {hasTLS && (
        <Collapse title={'TLS Details (' + ((e.tls_snis || []).length) + ' SNIs)'} open={true}>
          {e.tls_snis?.length > 0 && (
            <div style={{ marginBottom: 6 }}>
              <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 3 }}>SNI (Server Name)</div>
              {e.tls_snis.map(s => <div key={s} style={{ fontSize: 11, padding: '2px 0' }}>{s}</div>)}
            </div>
          )}
          {e.tls_versions?.length > 0 && (
            <div style={{ marginBottom: 6 }}>
              <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 3 }}>TLS Versions</div>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {e.tls_versions.map(v => <Tag key={v} color="#2dd4bf" small>{v}</Tag>)}
              </div>
            </div>
          )}
          {e.tls_selected_ciphers?.length > 0 && (
            <div style={{ marginBottom: 6 }}>
              <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 3 }}>Selected Cipher</div>
              {e.tls_selected_ciphers.map(c => <div key={c} style={{ fontSize: 10, color: 'var(--acG)', padding: '2px 0' }}>{c}</div>)}
            </div>
          )}
          {e.tls_ciphers?.length > 0 && (
            <Collapse title={'Offered Ciphers (' + e.tls_ciphers.length + ')'}>
              {e.tls_ciphers.map(c => <div key={c} style={{ fontSize: 10, color: 'var(--txM)', padding: '1px 0' }}>{c}</div>)}
            </Collapse>
          )}
          {(e.ja3_hashes?.length > 0 || e.ja4_hashes?.length > 0) && (
            <div style={{ marginTop: 6, paddingTop: 6, borderTop: '1px solid var(--bd)' }}>
              {e.ja3_hashes?.length > 0 && (
                <div style={{ marginBottom: 4 }}>
                  {e.ja3_hashes.map(h => (
                    <div key={h} style={{ display: 'flex', alignItems: 'baseline', gap: 5, flexWrap: 'wrap', marginBottom: 1 }}>
                      <span style={{ fontSize: 9, color: 'var(--txD)', flexShrink: 0 }}>JA3</span>
                      <JA3Badge hash={h} apps={e.ja3_apps || []} />
                    </div>
                  ))}
                </div>
              )}
              {e.ja4_hashes?.length > 0 && (
                <div>
                  {e.ja4_hashes.map(h => (
                    <div key={h} style={{ display: 'flex', alignItems: 'baseline', gap: 5, flexWrap: 'wrap', marginBottom: 1 }}>
                      <span style={{ fontSize: 9, color: 'var(--txD)', flexShrink: 0 }}>JA4</span>
                      <span style={{ fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--acP)', wordBreak: 'break-all' }}>{h}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </Collapse>
      )}

      {hasHTTP && (
        <Collapse title="HTTP Hosts" open>
          {e.http_hosts.map(h => <div key={h} style={{ fontSize: 11, padding: '2px 0' }}>{h}</div>)}
        </Collapse>
      )}

      {hasDNS && (
        <Collapse title={'DNS Queries (' + e.dns_queries.length + ')'} open>
          {e.dns_queries.slice(0, 20).map(q => <div key={q} style={{ fontSize: 10, padding: '2px 0', color: 'var(--txM)' }}>{q}</div>)}
        </Collapse>
      )}

      <Collapse title={'Sessions on this edge (' + edgeSessions.length + ')'} open={true}>
        {edgeSessions.length === 0 && !loadingMore && (
          <div style={{ fontSize: 10, color: 'var(--txD)' }}>
            No sessions found
            {fetchedSessions.length === 0 && (
              <span className="hr" onClick={loadMoreSessions}
                style={{ marginLeft: 6, color: 'var(--ac)', cursor: 'pointer' }}>Search</span>
            )}
          </div>
        )}
        {(expanded ? edgeSessions : edgeSessions.slice(0, EDGE_SESSION_PAGE)).map((s, i) => (
          <div key={i} className="hr" onClick={() => onSelectSession && onSelectSession(s, edgeSessions)}
            style={{ padding: '6px 4px', borderBottom: '1px solid var(--bd)', cursor: 'pointer', borderRadius: 3 }}>
            <div style={{ fontSize: 10, fontWeight: 500 }}>
              {s.initiator_ip || s.src_ip}:{s.initiator_port || s.src_port} → {s.responder_ip || s.dst_ip}:{s.responder_port || s.dst_port}
            </div>
            <div style={{ display: 'flex', gap: 4, marginTop: 3, alignItems: 'center', flexWrap: 'wrap' }}>
              <span style={{ fontSize: 9, color: 'var(--txM)' }}>
                {s.start_time ? fT(s.start_time) + ' · ' : ''}{fN(s.packet_count)} pkts · {fB(s.total_bytes)} · {fD(s.duration)}
              </span>
              {s.has_handshake && <Tag color="#3fb950" small tip="TCP Handshake completed (SYN→SYN+ACK→ACK)">HS</Tag>}
              {s.has_reset && <Tag color="#f85149" small tip="Connection reset (abrupt termination)">RST</Tag>}
              {s.has_fin && <Tag color="#d29922" small tip="Connection finished (graceful close)">FIN</Tag>}
            </div>
          </div>
        ))}
        {!expanded && edgeSessions.length > EDGE_SESSION_PAGE && (
          <button className="btn" onClick={() => { setExpanded(true); if (fetchedSessions.length === 0) loadMoreSessions(); }}
            disabled={loadingMore}
            style={{ fontSize: 9, padding: '3px 10px', marginTop: 6, width: '100%' }}>
            {loadingMore ? 'Loading…' : `Show more (${edgeSessions.length - EDGE_SESSION_PAGE} remaining)`}
          </button>
        )}
        {loadingMore && edgeSessions.length === 0 && (
          <div style={{ fontSize: 10, color: 'var(--txD)', padding: 4 }}>Loading…</div>
        )}
      </Collapse>

      {/* Notes */}
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
