import React, { useState, useEffect, useCallback } from 'react';
import Tag from '../../components/Tag';
import Collapse from '../../components/Collapse';
import Row from '../../components/Row';
import { fN, fB, fD, fT } from '../../utils';
import { fetchEdgeSessions, fetchEdgeDetail } from '../../api';

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

export default function EdgeDetail({ edge: e, pColors, onClear, nodes = [], onSelectSession, annotations = [], onSaveNote, clusterNames, onFlagEvent }) {
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
  const [edgeSessions, setEdgeSessions] = useState([]);
  const [sessionTotal, setSessionTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState(false);

  // Lazy-fetched detail fields (TLS/HTTP/DNS/JA3/JA4 — not in graph summary)
  // Note: fetched without filter params → shows global-capture scope for this edge.
  // Filter-aware detail can be added later by passing graphParams from the parent.
  const [detail, setDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Fetch sessions from canonical /api/edge-sessions endpoint when edge changes
  useEffect(() => {
    if (!edgeId) { setEdgeSessions([]); setSessionTotal(0); return; }
    setExpanded(false);
    setLoading(true);
    fetchEdgeSessions(edgeId)
      .then(d => { setEdgeSessions(d.sessions || []); setSessionTotal(d.total ?? 0); })
      .catch(() => { setEdgeSessions([]); setSessionTotal(0); })
      .finally(() => setLoading(false));
  }, [edgeId]);

  // Lazy-fetch edge detail (TLS/HTTP/DNS fields) when edge changes
  useEffect(() => {
    if (!edgeId) { setDetail(null); return; }
    setDetail(null);
    setDetailLoading(true);
    fetchEdgeDetail(edgeId)
      .then(d => setDetail(d))
      .catch(() => setDetail(null))
      .finally(() => setDetailLoading(false));
  }, [edgeId]);

  if (!e) return null;

  // Use fetched detail when available; fall back to boolean hints on the edge summary
  const hasTLS  = detail ? (detail.tls_snis?.length > 0 || detail.tls_versions?.length > 0 || detail.tls_ciphers?.length > 0 || detail.ja3_hashes?.length > 0 || detail.ja4_hashes?.length > 0) : e.has_tls;
  const hasDNS  = detail ? detail.dns_queries?.length > 0  : e.has_dns;
  const hasHTTP = detail ? detail.http_hosts?.length > 0   : e.has_http;

  return (
    <div className="fi" style={{ padding: 16, overflowY: 'auto', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <div className="sh" style={{ marginBottom: 0 }}>Edge Detail</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {onFlagEvent && (
            <button className="btn" onClick={onFlagEvent}
              title="Flag this edge as an Event"
              style={{
                padding: '3px 6px',
                color: '#f85149', borderColor: '#f85149',
                display: 'flex', alignItems: 'center',
              }}>
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>
            </button>
          )}
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
        {(e.src_ports?.length > 0 || e.dst_ports?.length > 0) && (
          <div style={{ display: 'flex', gap: 4, alignItems: 'baseline', padding: '2px 0', fontSize: 11 }}>
            <span style={{ color: 'var(--txD)', minWidth: 90, flexShrink: 0 }}>Ports</span>
            <span style={{ color: 'var(--txM)', fontFamily: 'var(--fn)', fontSize: 10 }}>
              <span style={{ color: 'var(--acG)' }}>
                {e.src_ports?.length > 0
                  ? ':' + e.src_ports.slice(0, 8).join(', :') + (e.src_ports.length > 8 ? '…' : '')
                  : '*'}
              </span>
              <span style={{ color: 'var(--txD)', margin: '0 4px' }}>→</span>
              <span style={{ color: 'var(--txM)' }}>
                {e.dst_ports?.length > 0
                  ? ':' + e.dst_ports.slice(0, 8).join(', :') + (e.dst_ports.length > 8 ? '…' : '')
                  : '*'}
              </span>
            </span>
          </div>
        )}
      </div>

      {detailLoading && (e.has_tls || e.has_http || e.has_dns) && (
        <div style={{ fontSize: 10, color: 'var(--txD)', padding: '6px 0' }}>Loading protocol details…</div>
      )}

      {hasTLS && detail && (
        <Collapse title={'TLS Details (' + ((detail.tls_snis || []).length) + ' SNIs)'} open={true}>
          {detail.tls_snis?.length > 0 && (
            <div style={{ marginBottom: 6 }}>
              <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 3 }}>SNI (Server Name)</div>
              {detail.tls_snis.map(s => <div key={s} style={{ fontSize: 11, padding: '2px 0' }}>{s}</div>)}
            </div>
          )}
          {detail.tls_versions?.length > 0 && (
            <div style={{ marginBottom: 6 }}>
              <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 3 }}>TLS Versions</div>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {detail.tls_versions.map(v => <Tag key={v} color="#2dd4bf" small>{v}</Tag>)}
              </div>
            </div>
          )}
          {detail.tls_selected_ciphers?.length > 0 && (
            <div style={{ marginBottom: 6 }}>
              <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 3 }}>Selected Cipher</div>
              {detail.tls_selected_ciphers.map(c => <div key={c} style={{ fontSize: 10, color: 'var(--acG)', padding: '2px 0' }}>{c}</div>)}
            </div>
          )}
          {detail.tls_ciphers?.length > 0 && (
            <Collapse title={'Offered Ciphers (' + detail.tls_ciphers.length + ')'}>
              {detail.tls_ciphers.map(c => <div key={c} style={{ fontSize: 10, color: 'var(--txM)', padding: '1px 0' }}>{c}</div>)}
            </Collapse>
          )}
          {(detail.ja3_hashes?.length > 0 || detail.ja4_hashes?.length > 0) && (
            <div style={{ marginTop: 6, paddingTop: 6, borderTop: '1px solid var(--bd)' }}>
              {detail.ja3_hashes?.length > 0 && (
                <div style={{ marginBottom: 4 }}>
                  {detail.ja3_hashes.map(h => (
                    <div key={h} style={{ display: 'flex', alignItems: 'baseline', gap: 5, flexWrap: 'wrap', marginBottom: 1 }}>
                      <span style={{ fontSize: 9, color: 'var(--txD)', flexShrink: 0 }}>JA3</span>
                      <JA3Badge hash={h} apps={detail.ja3_apps || []} />
                    </div>
                  ))}
                </div>
              )}
              {detail.ja4_hashes?.length > 0 && (
                <div>
                  {detail.ja4_hashes.map(h => (
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

      {hasHTTP && detail && (
        <Collapse title="HTTP Hosts" open>
          {detail.http_hosts.map(h => <div key={h} style={{ fontSize: 11, padding: '2px 0' }}>{h}</div>)}
        </Collapse>
      )}

      {hasDNS && detail && (
        <Collapse title={'DNS Queries (' + detail.dns_queries.length + ')'} open>
          {detail.dns_queries.slice(0, 20).map(q => <div key={q} style={{ fontSize: 10, padding: '2px 0', color: 'var(--txM)' }}>{q}</div>)}
        </Collapse>
      )}

      <Collapse title={'Sessions on this edge (' + (sessionTotal || edgeSessions.length) + ')'} open={true}>
        {edgeSessions.length === 0 && !loading && (
          <div style={{ fontSize: 10, color: 'var(--txD)' }}>No sessions found</div>
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
          <button className="btn" onClick={() => setExpanded(true)}
            style={{ fontSize: 9, padding: '3px 10px', marginTop: 6, width: '100%' }}>
            Show more ({edgeSessions.length - EDGE_SESSION_PAGE} remaining)
          </button>
        )}
        {loading && edgeSessions.length === 0 && (
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
