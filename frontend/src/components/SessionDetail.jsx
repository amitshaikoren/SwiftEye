import React, { useState, useEffect, useCallback, useRef } from 'react';
import Tag from './Tag';
import FlagBadge from './FlagBadge';
import Collapse from './Collapse';
import Row from './Row';
import { fN, fB, fD } from '../utils';
import { fetchSessionDetail, runResearchChart } from '../api';


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

// Inline Seq/Ack Timeline chart — calls the research endpoint directly
function SeqAckChart({ sessionId, session }) {
  const [figure, setFigure] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [mode, setMode] = useState('time');  // 'time' | 'seqack'
  const plotRef = useRef(null);

  useEffect(() => {
    if (!figure || !plotRef.current || !window.Plotly) return;
    window.Plotly.react(plotRef.current, figure.data, figure.layout, {
      responsive: true, displayModeBar: false,
    });
  }, [figure]);

  async function handleRun() {
    setLoading(true); setError(''); setFigure(null);
    try {
      const res = await runResearchChart('seq_ack_timeline', { session_id: sessionId, mode });
      setFigure(res.figure);
    } catch (e) {
      setError(e.message || 'Chart failed');
    } finally {
      setLoading(false);
    }
  }

  const isnInit = session?.seq_isn_init;
  const isnResp = session?.seq_isn_resp;

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
        <div style={{ fontSize: 10, color: 'var(--txD)', flex: 1 }}>
          {mode === 'time'
            ? 'Bytes sent over time. Slope = throughput, flat = stall, step back = retransmit.'
            : 'SEQ vs ACK (both normalized). Diagonal = healthy flow, flat = one side stopped.'}
        </div>
        <div style={{ display: 'flex', gap: 2 }}>
          <button className={'btn' + (mode === 'time' ? ' on' : '')}
            onClick={() => { setMode('time'); setFigure(null); }}
            style={{ fontSize: 9 }}>Bytes/time</button>
          <button className={'btn' + (mode === 'seqack' ? ' on' : '')}
            onClick={() => { setMode('seqack'); setFigure(null); }}
            style={{ fontSize: 9 }}>SEQ/ACK</button>
        </div>
        <button className="btn" onClick={handleRun} disabled={loading}
          style={{ fontSize: 10, padding: '3px 12px', background: loading ? undefined : 'rgba(88,166,255,.1)', borderColor: 'var(--ac)', color: 'var(--ac)' }}>
          {loading ? '…' : 'Run'}
        </button>
      </div>
      {error && (
        <div style={{ fontSize: 10, color: 'var(--acR)', padding: '8px 0' }}>{error}</div>
      )}
      {!figure && !loading && !error && (
        <div style={{ fontSize: 10, color: 'var(--txD)', textAlign: 'center', padding: '32px 0' }}>
          Click Run to compute the chart
        </div>
      )}
      {loading && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 260, color: 'var(--txD)', fontSize: 11 }}>
          Computing…
        </div>
      )}
      {figure && !loading && (
        <div ref={plotRef} style={{ width: '100%', height: 260 }} />
      )}
      {/* ISN reference — shown once chart is loaded or always if we have session data */}
      {(isnInit > 0 || isnResp > 0) && (
        <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 2 }}>
          <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 2 }}>Initial sequence numbers (ISN)</div>
          {isnInit > 0 && (
            <div style={{ fontSize: 9, fontFamily: 'var(--fn)', display: 'flex', gap: 6, alignItems: 'center' }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#3fb950', flexShrink: 0, display: 'inline-block' }} />
              <span style={{ color: 'var(--txD)' }}>Init</span>
              <span style={{ color: 'var(--txM)' }}>{isnInit.toLocaleString()}</span>
            </div>
          )}
          {isnResp > 0 && (
            <div style={{ fontSize: 9, fontFamily: 'var(--fn)', display: 'flex', gap: 6, alignItems: 'center' }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#58a6ff', flexShrink: 0, display: 'inline-block' }} />
              <span style={{ color: 'var(--txD)' }}>Resp</span>
              <span style={{ color: 'var(--txM)' }}>{isnResp.toLocaleString()}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function SessionDetail({ session: s, onBack, pColors, onTabChange, siblings = [], onNavigate }) {
  const [tab, setTab] = useState('overview');
  const [pkts, setPkts] = useState([]);
  const [ld, setLd] = useState(false);
  const [showHex, setShowHex] = useState(false);

  // Sibling navigation — index within siblings sorted by start_time
  const sibIdx = siblings.findIndex(x => x.id === s.id);
  const hasSibs = siblings.length > 1;
  const goPrev = () => { if (sibIdx > 0) onNavigate?.(siblings[sibIdx - 1], siblings); };
  const goNext = () => { if (sibIdx < siblings.length - 1) onNavigate?.(siblings[sibIdx + 1], siblings); };

  // Reset tab + packet data when navigating to a different session
  useEffect(() => {
    setTab('overview');
    setPkts([]);
    setLd(false);
    setShowHex(false);
  }, [s.id]);

  function switchTab(t) {
    setTab(t);
    onTabChange?.(t);
  }

  const loadP = useCallback(async () => {
    if (ld || pkts.length) return;
    setLd(true);
    try {
      const d = await fetchSessionDetail(s.id);
      setPkts(d.packets || []);
    } catch (e) {
      console.error('Session detail error:', e);
    }
    setLd(false);
  }, [s.id, ld, pkts.length]);

  useEffect(() => {
    if (tab === 'packets') loadP();
  }, [tab, loadP]);

  return (
    <div className="fi" style={{ padding: 16, overflowY: 'auto', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
        <div className="sh" style={{ marginBottom: 0 }}>Session Detail</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          {hasSibs && (
            <>
              <button className="btn" onClick={goPrev} disabled={sibIdx <= 0}
                style={{ fontSize: 11, padding: '1px 7px', opacity: sibIdx <= 0 ? 0.3 : 1 }}>‹</button>
              <span style={{ fontSize: 9, color: 'var(--txD)', minWidth: 36, textAlign: 'center' }}>
                {sibIdx + 1} / {siblings.length}
              </span>
              <button className="btn" onClick={goNext} disabled={sibIdx >= siblings.length - 1}
                style={{ fontSize: 11, padding: '1px 7px', opacity: sibIdx >= siblings.length - 1 ? 0.3 : 1 }}>›</button>
            </>
          )}
          <button className="btn" onClick={onBack} style={{ marginLeft: hasSibs ? 4 : 0 }}>✕</button>
        </div>
      </div>

      <div style={{ fontSize: 12, fontWeight: 500, marginBottom: 4, wordBreak: 'break-all' }}>
        {s.initiator_ip ? (
          <><span style={{ color: 'var(--acG)' }}>{s.initiator_ip}:{s.initiator_port}</span> → {s.responder_ip}:{s.responder_port}</>
        ) : (
          <>{s.src_ip}:{s.src_port} ↔ {s.dst_ip}:{s.dst_port}</>
        )}
      </div>

      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 12 }}>
        <Tag color={pColors[s.protocol] || '#64748b'}>{s.protocol}</Tag>
        <Tag color="#8b949e">{s.transport}</Tag>
        {s.has_handshake && <Tag color="#3fb950">Handshake</Tag>}
        {s.has_fin && <Tag color="#d29922">FIN</Tag>}
        {s.has_reset && <Tag color="#f85149">RST</Tag>}
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 2, marginBottom: 12, borderBottom: '1px solid var(--bd)', paddingBottom: 6 }}>
        {['overview', 'packets', 'payload', 'charts'].map(t => (
          <button key={t} className={'btn' + (tab === t ? ' on' : '')}
            onClick={() => switchTab(t)} style={{ textTransform: 'uppercase', letterSpacing: '.05em', fontSize: 9 }}>{t}</button>
        ))}
      </div>

      {tab === 'overview' && (
        <div>
          {/* ── Top fields — always visible ── */}
          <Row l="Packets" v={fN(s.packet_count)} />
          <Row l="Total bytes" v={fB(s.total_bytes)} />
          <Row l="Duration" v={fD(s.duration)} />
          {s.initiator_ip && <Row l="Initiator" v={s.initiator_ip + ':' + s.initiator_port} />}
          {s.responder_ip && <Row l="Responder" v={s.responder_ip + ':' + s.responder_port} />}

          {/* ── Directional traffic ── */}
          <Collapse title="Directional Traffic" open={true}>
            <Row l="→ Initiator sent" v={fN(s.fwd_packets) + ' pkts / ' + fB(s.fwd_bytes)} />
            {s.fwd_payload_bytes > 0 && <Row l="  payload" v={fB(s.fwd_payload_bytes)} />}
            <Row l="← Responder sent" v={fN(s.rev_packets) + ' pkts / ' + fB(s.rev_bytes)} />
            {s.rev_payload_bytes > 0 && <Row l="  payload" v={fB(s.rev_payload_bytes)} />}
          </Collapse>

          {/* ── Directional ports ── */}
          {((s.retransmits_fwd > 0 || s.retransmits_rev > 0 || s.out_of_order_fwd > 0 || s.out_of_order_rev > 0)) && (
            <Collapse title="TCP Reliability" open={true}>
              {(s.retransmits_fwd > 0 || s.retransmits_rev > 0) && (<>
                <Row l="Retransmits →" v={String(s.retransmits_fwd ?? 0)} />
                <Row l="Retransmits ←" v={String(s.retransmits_rev ?? 0)} />
              </>)}
              {(s.out_of_order_fwd > 0 || s.out_of_order_rev > 0) && (<>
                <Row l="Out-of-order →" v={String(s.out_of_order_fwd ?? 0)} />
                <Row l="Out-of-order ←" v={String(s.out_of_order_rev ?? 0)} />
              </>)}
              {(s.dup_acks_fwd > 0 || s.dup_acks_rev > 0) && (
                <Row l="Dup-ACK events" v={String((s.dup_acks_fwd ?? 0) + (s.dup_acks_rev ?? 0))} />
              )}
            </Collapse>
          )}

          {(s.initiator_ports?.length > 0 || s.responder_ports?.length > 0) && (
            <Collapse title="Ports" open={true}>
              {s.initiator_ports?.length > 0 && (
                <Row l="Initiator →" v={s.initiator_ports.slice(0, 10).join(', ') + (s.initiator_ports.length > 10 ? '…' : '')} />
              )}
              {s.responder_ports?.length > 0 && (
                <Row l="Responder →" v={s.responder_ports.slice(0, 10).join(', ') + (s.responder_ports.length > 10 ? '…' : '')} />
              )}
            </Collapse>
          )}

          {/* ── TTL by direction ── */}
          {(s.ttls_initiator?.length > 0 || s.ttls_responder?.length > 0) && (
            <Collapse title="TTL" open={true}>
              {s.ttls_initiator?.length > 0 && <Row l="Initiator TTL" v={s.ttls_initiator.join(', ')} />}
              {s.ttls_responder?.length > 0 && <Row l="Responder TTL" v={s.ttls_responder.join(', ')} />}
            </Collapse>
          )}

          {/* ── IP header fields — per direction ── */}
          {s.ip_version > 0 && (
            <Collapse title={s.ip_version === 6 ? 'IPv6 Header' : 'IPv4 Header'}>
              {s.ip_version === 4 && (() => {
                const dscpName = v => {
                  const names = {0:'CS0 (best-effort)',8:'CS1',16:'CS2',24:'CS3',32:'CS4',40:'CS5',48:'CS6',56:'CS7',
                    10:'AF11',12:'AF12',14:'AF13',18:'AF21',20:'AF22',22:'AF23',26:'AF31',28:'AF32',30:'AF33',
                    34:'AF41',36:'AF42',38:'AF43',46:'EF (voice/video)',44:'VA'};
                  return names[v] ? `${v} — ${names[v]}` : String(v);
                };
                const ecnName = v => ['','ECT1','ECT0','CE'][v] || String(v);
                const ipIdStr = (mn, mx) => mn == null ? null :
                  mn === mx
                    ? `0x${mn.toString(16).padStart(4,'0')} (${mn})`
                    : `0x${mn.toString(16).padStart(4,'0')}–0x${mx.toString(16).padStart(4,'0')} (${mn}–${mx})`;

                const DirSection = ({ label, prefix }) => (
                  <div style={{ marginBottom: 8 }}>
                    <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 4 }}>{label}</div>
                    <Row l="DF" v={s[`${prefix}_df_set`] ? 'set' : 'not set'} />
                    <Row l="MF" v={s[`${prefix}_mf_set`] ? 'set — fragmented' : 'not set'} />
                    {s[`${prefix}_frag_seen`] && <Row l="Fragmentation" v="observed" />}
                    {ipIdStr(s[`${prefix}_ip_id_min`], s[`${prefix}_ip_id_max`]) &&
                      <Row l="IP ID range" v={ipIdStr(s[`${prefix}_ip_id_min`], s[`${prefix}_ip_id_max`])} />}
                    {s[`${prefix}_dscp_values`]?.length > 0 &&
                      <Row l="DSCP" v={s[`${prefix}_dscp_values`].map(dscpName).join(', ')} />}
                    {s[`${prefix}_ecn_values`]?.some(v => v > 0) &&
                      <Row l="ECN" v={s[`${prefix}_ecn_values`].filter(v => v > 0).map(ecnName).join(', ')} />}
                  </div>
                );

                return (
                  <>
                    <DirSection label={`Initiator → (${s.initiator_ip || s.src_ip})`} prefix="fwd" />
                    <div style={{ height: 1, background: 'var(--bd)', margin: '4px 0 8px' }} />
                    <DirSection label={`Responder → (${s.responder_ip || s.dst_ip})`} prefix="rev" />
                  </>
                );
              })()}
              {s.ip_version === 6 && (
                <>
                  {s.ip6_flow_labels?.length > 0 && (
                    <Row l="Flow label" v={s.ip6_flow_labels.map(v => `0x${v.toString(16)}`).join(', ')} />
                  )}
                  {[...new Set([...(s.fwd_dscp_values||[]), ...(s.rev_dscp_values||[])])].length > 0 && (
                    <Row l="DSCP" v={[...new Set([...(s.fwd_dscp_values||[]), ...(s.rev_dscp_values||[])])].map(v =>
                      ({0:'CS0 (best-effort)',46:'EF (voice/video)',40:'CS5',34:'AF41'})[v] || String(v)).join(', ')} />
                  )}
                  {[...(s.fwd_ecn_values||[]), ...(s.rev_ecn_values||[])].some(v => v > 0) && (
                    <Row l="ECN" v={[...new Set([...(s.fwd_ecn_values||[]), ...(s.rev_ecn_values||[])])].filter(v => v > 0).map(v => ['','ECT1','ECT0','CE'][v]||String(v)).join(', ')} />
                  )}
                </>
              )}
            </Collapse>
          )}

          {/* ── TLS ── */}
          {(s.tls_snis?.length > 0 || s.tls_versions?.length > 0 || s.tls_selected_ciphers?.length > 0 || s.ja3_hashes?.length > 0 || s.ja4_hashes?.length > 0 || s.tls_cert) && (
            <Collapse title={
              'TLS'
              + (s.tls_versions?.length ? ' ' + s.tls_versions[0] : '')
              + (s.tls_snis?.length ? ' — ' + s.tls_snis[0] : '')
            } open={true}>
              {s.tls_snis?.length > 0 && (
                <div style={{ marginBottom: 6 }}>
                  <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 3 }}>SNI</div>
                  {s.tls_snis.map(sni => <div key={sni} style={{ fontSize: 11, padding: '2px 0' }}>{sni}</div>)}
                </div>
              )}
              {s.tls_versions?.length > 0 && (
                <div style={{ marginBottom: 6 }}>
                  <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 3 }}>Version</div>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    {s.tls_versions.map(v => <Tag key={v} color="#2dd4bf" small>{v}</Tag>)}
                  </div>
                </div>
              )}
              {s.tls_selected_ciphers?.length > 0 && (
                <div style={{ marginBottom: 6 }}>
                  <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 3 }}>Selected cipher</div>
                  {s.tls_selected_ciphers.map(c => <div key={c} style={{ fontSize: 10, color: 'var(--acG)', padding: '2px 0' }}>{c}</div>)}
                </div>
              )}
              {/* Certificate — extracted from TLS Certificate message */}
              {s.tls_cert && (
                <Collapse title="Certificate" open={true}>
                  {s.tls_cert.subject_cn && <Row l="Subject" v={s.tls_cert.subject_cn} />}
                  {s.tls_cert.issuer    && <Row l="Issuer"  v={s.tls_cert.issuer} />}
                  {s.tls_cert.not_before && s.tls_cert.not_after && (
                    <Row l="Valid" v={`${s.tls_cert.not_before} → ${s.tls_cert.not_after}`} />
                  )}
                  {s.tls_cert.sans?.length > 0 && (
                    <div style={{ marginTop: 4 }}>
                      <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 3 }}>SANs ({s.tls_cert.sans.length})</div>
                      {s.tls_cert.sans.slice(0, 10).map(san => (
                        <div key={san} style={{ fontSize: 9, fontFamily: 'var(--fn)', color: 'var(--txM)', padding: '1px 0' }}>{san}</div>
                      ))}
                      {s.tls_cert.sans.length > 10 && (
                        <div style={{ fontSize: 9, color: 'var(--txD)' }}>+{s.tls_cert.sans.length - 10} more</div>
                      )}
                    </div>
                  )}
                  {s.tls_cert.serial && (
                    <Row l="Serial" v={s.tls_cert.serial} />
                  )}
                </Collapse>
              )}
              {(s.ja3_hashes?.length > 0 || s.ja4_hashes?.length > 0) && (
                <div style={{ marginTop: 4, paddingTop: 4, borderTop: '1px solid var(--bd)' }}>
                  {s.ja3_hashes?.map(h => (
                    <div key={h} style={{ marginBottom: 2 }}>
                      <span style={{ fontSize: 9, color: 'var(--txD)', marginRight: 5 }}>JA3</span>
                      <JA3Badge hash={h} apps={s.ja3_apps || []} />
                    </div>
                  ))}
                  {s.ja4_hashes?.map(h => (
                    <div key={h} style={{ marginBottom: 2, display: 'flex', alignItems: 'baseline', gap: 6, flexWrap: 'wrap' }}>
                      <span style={{ fontSize: 9, color: 'var(--txD)', flexShrink: 0 }}>JA4</span>
                      <span style={{ fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--acP)', wordBreak: 'break-all' }}>{h}</span>
                    </div>
                  ))}
                </div>
              )}
              {s.tls_ciphers?.length > 0 && (
                <Collapse title={'Offered ciphers (' + s.tls_ciphers.length + ')'}>
                  {s.tls_ciphers.map(c => <div key={c} style={{ fontSize: 10, color: 'var(--txM)', padding: '1px 0' }}>{c}</div>)}
                </Collapse>
              )}
            </Collapse>
          )}

          {/* ── HTTP / DNS ── */}
          {s.http_hosts?.length > 0 && (
            <Collapse title="HTTP Hosts" open>
              {s.http_hosts.map(h => <div key={h} style={{ fontSize: 11, padding: '2px 0' }}>{h}</div>)}
            </Collapse>
          )}
          {/* SSH details */}
          {s.ssh_versions?.length > 0 && (
            <Collapse title="SSH" open={true}>
              {s.ssh_versions.map(v => (
                <div key={v} style={{ fontSize: 11, padding: '2px 0', fontFamily: 'var(--fn)', color: 'var(--acG)' }}>{v}</div>
              ))}
            </Collapse>
          )}

          {/* FTP details */}
          {(s.ftp_usernames?.length > 0 || s.ftp_transfer_files?.length > 0 || s.ftp_has_credentials) && (
            <Collapse title={'FTP' + (s.ftp_has_credentials ? ' ⚠ Credentials' : '')} open={true}>
              {s.ftp_has_credentials && (
                <div style={{ fontSize: 10, color: 'var(--acO)', marginBottom: 4 }}>⚠ USER/PASS sequence detected — credentials in cleartext</div>
              )}
              {s.ftp_usernames?.length > 0 && <Row l="Username(s)" v={s.ftp_usernames.join(', ')} />}
              {s.ftp_transfer_files?.length > 0 && (
                <div style={{ marginTop: 4 }}>
                  <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 2 }}>Files transferred</div>
                  {s.ftp_transfer_files.slice(0, 10).map((f, i) => (
                    <div key={i} style={{ fontSize: 10, color: 'var(--txD)', padding: '1px 0', fontFamily: 'var(--fn)' }}>{f}</div>
                  ))}
                </div>
              )}
            </Collapse>
          )}

          {/* DHCP details */}
          {(s.dhcp_hostnames?.length > 0 || s.dhcp_vendor_classes?.length > 0 || s.dhcp_msg_types?.length > 0) && (
            <Collapse title="DHCP" open={true}>
              {s.dhcp_msg_types?.length > 0 && <Row l="Message types" v={s.dhcp_msg_types.join(' → ')} />}
              {s.dhcp_hostnames?.length > 0 && <Row l="Hostname(s)" v={s.dhcp_hostnames.join(', ')} />}
              {s.dhcp_vendor_classes?.length > 0 && (
                <div style={{ marginTop: 4 }}>
                  <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 2 }}>Vendor class</div>
                  {s.dhcp_vendor_classes.map(v => (
                    <div key={v} style={{ fontSize: 10, color: 'var(--txD)', fontFamily: 'var(--fn)' }}>{v}</div>
                  ))}
                </div>
              )}
            </Collapse>
          )}

          {/* SMB details */}
          {(s.smb_versions?.length > 0 || s.smb_tree_paths?.length > 0 || s.smb_filenames?.length > 0) && (
            <Collapse title={'SMB' + (s.smb_versions?.length ? ' (' + s.smb_versions.join(', ') + ')' : '')} open={true}>
              {s.smb_tree_paths?.length > 0 && (
                <div style={{ marginBottom: 6 }}>
                  <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 2 }}>Share paths</div>
                  {s.smb_tree_paths.map(p => (
                    <div key={p} style={{ fontSize: 10, color: 'var(--ac)', fontFamily: 'var(--fn)', padding: '1px 0' }}>{p}</div>
                  ))}
                </div>
              )}
              {s.smb_filenames?.length > 0 && (
                <div>
                  <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 2 }}>Filenames</div>
                  {s.smb_filenames.slice(0, 15).map(f => (
                    <div key={f} style={{ fontSize: 10, color: 'var(--txD)', fontFamily: 'var(--fn)', padding: '1px 0' }}>{f}</div>
                  ))}
                </div>
              )}
            </Collapse>
          )}

          {s.dns_queries?.length > 0 && (
            <Collapse title={'DNS Queries (' + s.dns_queries.length + ')'} open>
              {s.dns_queries.slice(0, 20).map((q, i) => (
                <div key={i} style={{ fontSize: 10, padding: '3px 0', borderBottom: '1px solid var(--bd)' }}>
                  <span style={{ color: '#fbbf24' }}>{q.qr}</span> {q.query}
                  {q.answers?.length > 0 && <span style={{ color: 'var(--txD)', marginLeft: 4 }}>→ {q.answers.join(', ')}</span>}
                </div>
              ))}
            </Collapse>
          )}

          {/* ── Window size: initial per direction + min/max (avg removed) ── */}
          {(s.window_min > 0 || s.init_window_initiator > 0) && (
            <Collapse title="Window Size">
              {s.init_window_initiator > 0 && <Row l="Init (initiator →)" v={fN(s.init_window_initiator)} />}
              {s.init_window_responder > 0 && <Row l="Init (responder →)" v={fN(s.init_window_responder)} />}
              {s.window_min > 0 && <Row l="Min / Max" v={fN(s.window_min) + ' / ' + fN(s.window_max)} />}
            </Collapse>
          )}

          {/* ── Advanced: TCP flags, seq/ack numbers, TCP options ── */}
          <Collapse title="Advanced">
            {Object.keys(s.flag_counts || {}).some(k => (s.flag_counts || {})[k] > 0) && (
              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 6 }}>TCP flags</div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4 }}>
                  {Object.entries(s.flag_counts || {}).filter(([, v]) => v > 0).map(([f, c]) => (
                    <div key={f} style={{
                      background: 'var(--bgC)', border: '1px solid var(--bd)',
                      borderRadius: 'var(--rs)', padding: '5px 8px',
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    }}>
                      <FlagBadge f={f} />
                      <span style={{ fontSize: 12, fontWeight: 600, fontFamily: 'var(--fd)' }}>{c}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {s.seq_first > 0 && (
              <div style={{ marginBottom: 8 }}>
                <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 4 }}>
                  Seq/ack — use SEQ/ACK tab for visual view
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
                  {s.seq_isn_init > 0 && <><div style={{ fontSize: 9, color: 'var(--txD)' }}>ISN initiator</div><div style={{ fontSize: 10, fontFamily: 'var(--fn)' }}>{fN(s.seq_isn_init)}</div></>}
                  {s.seq_isn_resp > 0 && <><div style={{ fontSize: 9, color: 'var(--txD)' }}>ISN responder</div><div style={{ fontSize: 10, fontFamily: 'var(--fn)' }}>{fN(s.seq_isn_resp)}</div></>}
                  <div style={{ fontSize: 9, color: 'var(--txD)' }}>First seq</div><div style={{ fontSize: 10, fontFamily: 'var(--fn)' }}>{fN(s.seq_first)}</div>
                  <div style={{ fontSize: 9, color: 'var(--txD)' }}>Last seq</div><div style={{ fontSize: 10, fontFamily: 'var(--fn)' }}>{fN(s.seq_last)}</div>
                  <div style={{ fontSize: 9, color: 'var(--txD)' }}>First ack</div><div style={{ fontSize: 10, fontFamily: 'var(--fn)' }}>{fN(s.ack_first)}</div>
                  <div style={{ fontSize: 9, color: 'var(--txD)' }}>Last ack</div><div style={{ fontSize: 10, fontFamily: 'var(--fn)' }}>{fN(s.ack_last)}</div>
                </div>
              </div>
            )}
            {s.tcp_options_seen?.length > 0 && (
              <div>
                <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 4 }}>TCP options</div>
                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                  {s.tcp_options_seen.map(o => <Tag key={o} color="#bc8cff">{o}</Tag>)}
                </div>
              </div>
            )}
          </Collapse>
        </div>
      )}

      {tab === 'payload' && (
        <div>
          {pkts.length === 0 && !ld && (
            <div style={{ fontSize: 10, color: 'var(--txD)', padding: '20px 0', textAlign: 'center' }}>
              <button className="btn" onClick={loadP} style={{ fontSize: 10 }}>Load packets</button>
              <div style={{ marginTop: 6, fontSize: 9, color: 'var(--txD)' }}>Packet data is loaded on demand</div>
            </div>
          )}
          {ld && <div style={{ color: 'var(--txD)', fontSize: 11, padding: 10 }}>Loading…</div>}
          {pkts.length > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
              <span style={{ fontSize: 10, color: 'var(--txD)' }}>{pkts.filter(p => p.payload_hex).length} packets with payload</span>
              <button className={'btn' + (showHex ? ' on' : '')}
                onClick={() => setShowHex(v => !v)}
                style={{ fontSize: 9, marginLeft: 'auto' }}>
                Hex
              </button>
            </div>
          )}
          {pkts.filter(p => p.payload_hex).slice(0, 20).map((p, i) => {
            // Parse the dump rows into { offset, hex, ascii } once
            const rows = (p.payload_hex || '').split('\n').filter(Boolean).map(row => {
              const sp1 = row.indexOf('  ');
              if (sp1 < 0) return { offset: row, hex: '', ascii: '' };
              const rest = row.slice(sp1 + 2);
              const sp2 = rest.lastIndexOf('  ');
              return {
                offset: row.slice(0, sp1),
                hex: sp2 >= 0 ? rest.slice(0, sp2) : rest,
                ascii: sp2 >= 0 ? rest.slice(sp2 + 2) : '',
              };
            });
            const copyAscii = () => navigator.clipboard?.writeText(rows.map(r => r.ascii).join(''));
            const copyHex   = () => navigator.clipboard?.writeText(rows.map(r => r.hex).join('\n'));
            const copyRaw   = () => navigator.clipboard?.writeText(p.payload_bytes || '');

            return (
              <div key={i} style={{ marginBottom: 8, background: 'var(--bgC)', border: '1px solid var(--bd)', borderRadius: 6, overflow: 'hidden' }}>
                {/* Header row */}
                <div style={{ padding: '5px 10px', borderBottom: '1px solid var(--bd)', display: 'flex', gap: 6, alignItems: 'center', fontSize: 10, flexWrap: 'wrap' }}>
                  <span style={{ color: 'var(--txD)', flexShrink: 0 }}>#{i + 1}</span>
                  <span style={{ color: 'var(--acG)', flexShrink: 0 }}>{p.src_ip}:{p.src_port}</span>
                  <span style={{ color: 'var(--txD)' }}>→</span>
                  <span style={{ color: 'var(--txM)', flexShrink: 0 }}>{p.dst_ip}:{p.dst_port}</span>
                  <span style={{ color: 'var(--txD)', flexShrink: 0 }}>{p.payload_len}B</span>
                  {/* IP header quick-view */}
                  {p.ip_version === 4 && (
                    <span style={{ color: 'var(--txD)', fontSize: 9, flexShrink: 0 }}>
                      TTL:{p.ttl}
                      {p.ip_flags & 2 ? ' DF' : ''}
                      {p.ip_flags & 1 ? ' MF' : ''}
                      {p.dscp > 0 ? ` DSCP:${p.dscp}` : ''}
                      {p.ecn > 0 ? ` ECN:${['','ECT1','ECT0','CE'][p.ecn]}` : ''}
                    </span>
                  )}
                  {p.ip_version === 6 && (
                    <span style={{ color: 'var(--txD)', fontSize: 9, flexShrink: 0 }}>
                      HL:{p.ttl}
                      {p.dscp > 0 ? ` DSCP:${p.dscp}` : ''}
                      {p.ecn > 0 ? ` ECN:${['','ECT1','ECT0','CE'][p.ecn]}` : ''}
                      {p.ip6_flow_label > 0 ? ` FL:0x${p.ip6_flow_label.toString(16)}` : ''}
                    </span>
                  )}
                  {p.tcp_checksum > 0 && (
                    <span style={{ color: 'var(--txD)', fontSize: 9, flexShrink: 0 }}>
                      cksum:0x{p.tcp_checksum.toString(16).padStart(4, '0')}
                    </span>
                  )}
                  {/* Copy buttons */}
                  <div style={{ marginLeft: 'auto', display: 'flex', gap: 3, flexShrink: 0 }}>
                    <button className="btn" onClick={copyAscii} style={{ fontSize: 8, padding: '1px 5px' }} title="Copy ASCII text">ASCII</button>
                    <button className="btn" onClick={copyHex}   style={{ fontSize: 8, padding: '1px 5px' }} title="Copy hex dump">Hex</button>
                    <button className="btn" onClick={copyRaw}   style={{ fontSize: 8, padding: '1px 5px' }} title="Copy raw bytes as hex string">Raw</button>
                  </div>
                </div>
                {/* Dump — offset + ascii (default) or offset + hex + ascii (when Hex is on) */}
                <div style={{ padding: '6px 10px', overflowX: 'auto' }}>
                  <pre style={{ margin: 0, fontFamily: 'var(--fn)', fontSize: 9, lineHeight: 1.8, whiteSpace: 'pre', color: 'var(--txM)' }}>
                    {rows.map((row, ri) => (
                      <span key={ri}>
                        <span style={{ color: 'var(--txD)' }}>{row.offset}</span>
                        {'  '}
                        {showHex && <><span style={{ color: 'var(--ac)' }}>{row.hex}</span>{'  '}</>}
                        <span>{row.ascii}</span>
                        {'\n'}
                      </span>
                    ))}
                  </pre>
                </div>
              </div>
            );
          })}
          {pkts.length > 0 && pkts.filter(p => p.payload_hex).length === 0 && (
            <div style={{ fontSize: 10, color: 'var(--txD)', padding: '20px 0', textAlign: 'center' }}>
              No payload data in this session (packets may be headers-only or encrypted without extracted fields).
            </div>
          )}
          {pkts.filter(p => p.payload_hex).length > 20 && (
            <div style={{ fontSize: 9, color: 'var(--txD)', textAlign: 'center', marginTop: 4 }}>
              Showing first 20 packets with payload. Load all via Sessions → packet limit.
            </div>
          )}
        </div>
      )}

      {tab === 'charts' && (
        <SeqAckChart sessionId={s.id} session={s} />
      )}

      {tab === 'packets' && (
        <div style={{ maxHeight: 500, overflowY: 'auto' }}>
          {ld && <div style={{ color: 'var(--txD)', fontSize: 11, padding: 10 }}>Loading...</div>}
          {pkts.map((p, i) => (
            <div key={i} className="hr" style={{ fontSize: 10, padding: '5px 2px', borderBottom: '1px solid var(--bd)', borderRadius: 3 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--txD)' }}>#{i + 1}</span>
                <span>{p.src_ip}:{p.src_port} → {p.dst_ip}:{p.dst_port}</span>
                <span style={{ color: 'var(--txD)' }}>{p.length}B</span>
              </div>
              <div style={{ display: 'flex', gap: 4, marginTop: 2, alignItems: 'center', flexWrap: 'wrap' }}>
                {(p.tcp_flags_list || []).map(f => <FlagBadge key={f} f={f} />)}
                {p.ttl > 0 && <span style={{ color: 'var(--txD)' }}>TTL:{p.ttl}</span>}
                {p.window_size > 0 && <span style={{ color: 'var(--txD)' }}>Win:{fN(p.window_size)}</span>}
                {p.seq_num > 0 && <span style={{ color: 'var(--txD)' }}>Seq:{fN(p.seq_num)}</span>}
                {p.ack_num > 0 && <span style={{ color: 'var(--txD)' }}>Ack:{fN(p.ack_num)}</span>}
                {p.payload_len > 0 && <span style={{ color: 'var(--txD)' }}>PL:{p.payload_len}B</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
