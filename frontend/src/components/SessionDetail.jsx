import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import Tag from './Tag';
import FlagBadge from './FlagBadge';
import Collapse, { CollapseContext } from './Collapse';
import Row from './Row';
import { fN, fB, fD, sessionRefHash } from '../utils';
import { fetchSessionDetail, runResearchChart } from '../api';
import { sections as _allSections, getUnclaimedPrefixes, FallbackSection } from './session_sections';


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
/**
 * StreamView — Wireshark-style "Follow TCP Stream" conversation view.
 *
 * Merges consecutive same-direction payloads into turns, color-coded:
 *   Client (initiator) → green text
 *   Server (responder) → blue text
 * Shows ASCII by default with hex toggle. Supports copy.
 */
function StreamView({ pkts, session: s, loading }) {
  const [showMode, setShowMode] = useState('ascii'); // 'ascii' | 'hex' | 'raw'

  if (loading) return <div style={{ color: 'var(--txD)', fontSize: 11, padding: 10 }}>Loading…</div>;

  // Filter to packets with payload, sorted by time
  const withPayload = pkts
    .filter(p => p.payload_bytes || p.payload_hex)
    .sort((a, b) => a.timestamp - b.timestamp);

  if (withPayload.length === 0) {
    return (
      <div style={{ fontSize: 10, color: 'var(--txD)', padding: '20px 0', textAlign: 'center' }}>
        No payload data — packets may be headers-only or encrypted.
      </div>
    );
  }

  // Determine initiator: first packet's src is the client
  const initiatorIp = withPayload[0].src_ip;
  const initiatorPort = withPayload[0].src_port;

  // Build conversation turns: merge consecutive same-direction payloads
  const turns = [];
  let currentTurn = null;

  for (const p of withPayload) {
    const isClient = p.src_ip === initiatorIp && p.src_port === initiatorPort;
    const dir = isClient ? 'client' : 'server';

    // Decode payload
    let ascii = '';
    let hex = '';
    let raw = '';
    if (p.payload_bytes) {
      raw = p.payload_bytes;
      // Convert hex string to ASCII
      const bytes = [];
      for (let i = 0; i < raw.length; i += 2) {
        bytes.push(parseInt(raw.substr(i, 2), 16));
      }
      ascii = bytes.map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('');
      // Format hex in groups of 2 with spaces
      hex = raw.match(/.{1,2}/g)?.join(' ') || '';
    }

    if (currentTurn && currentTurn.dir === dir) {
      // Same direction — merge
      currentTurn.ascii += ascii;
      currentTurn.hex += (currentTurn.hex ? ' ' : '') + hex;
      currentTurn.raw += raw;
      currentTurn.bytes += p.payload_len || 0;
      currentTurn.packets++;
    } else {
      // New turn
      currentTurn = {
        dir,
        srcIp: p.src_ip,
        srcPort: p.src_port,
        dstIp: p.dst_ip,
        dstPort: p.dst_port,
        ascii,
        hex,
        raw,
        bytes: p.payload_len || 0,
        packets: 1,
        timestamp: p.timestamp,
      };
      turns.push(currentTurn);
    }
  }

  const totalClient = turns.filter(t => t.dir === 'client').reduce((a, t) => a + t.bytes, 0);
  const totalServer = turns.filter(t => t.dir === 'server').reduce((a, t) => a + t.bytes, 0);

  const copyAll = () => {
    const text = turns.map(t => {
      const label = t.dir === 'client' ? `>>> ${t.srcIp}:${t.srcPort}` : `<<< ${t.srcIp}:${t.srcPort}`;
      return `${label}\n${showMode === 'hex' ? t.hex : t.ascii}\n`;
    }).join('\n');
    navigator.clipboard?.writeText(text);
  };

  return (
    <div>
      {/* Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 10, color: 'var(--txD)' }}>
          {turns.length} turns · {withPayload.length} packets
        </span>
        <span style={{ fontSize: 9 }}>
          <span style={{ color: '#7ee787' }}>{fN(totalClient)}B</span>
          <span style={{ color: 'var(--txD)' }}> client, </span>
          <span style={{ color: '#79c0ff' }}>{fN(totalServer)}B</span>
          <span style={{ color: 'var(--txD)' }}> server</span>
        </span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 2 }}>
          {['ascii', 'hex', 'raw'].map(m => (
            <button key={m} className={'btn' + (showMode === m ? ' on' : '')}
              onClick={() => setShowMode(m)}
              style={{ fontSize: 8, padding: '2px 6px', textTransform: 'uppercase' }}>
              {m}
            </button>
          ))}
          <button className="btn" onClick={copyAll} style={{ fontSize: 8, padding: '2px 6px' }} title="Copy entire stream">
            Copy
          </button>
        </div>
      </div>

      {/* Stream conversation */}
      <div style={{
        background: '#0d1117', border: '1px solid var(--bd)', borderRadius: 8,
        maxHeight: 500, overflowY: 'auto', padding: 0,
        fontFamily: "'Cascadia Code', 'Fira Code', 'Consolas', monospace",
        fontSize: 11, lineHeight: 1.5,
      }}>
        {turns.map((turn, i) => {
          const isClient = turn.dir === 'client';
          const color = isClient ? '#7ee787' : '#79c0ff';
          const bgColor = isClient ? 'rgba(63,185,80,.04)' : 'rgba(88,166,255,.04)';
          const arrow = isClient ? '>>>' : '<<<';
          const content = showMode === 'hex' ? turn.hex
            : showMode === 'raw' ? turn.raw
            : turn.ascii;

          return (
            <div key={i} style={{ borderBottom: i < turns.length - 1 ? '1px solid rgba(255,255,255,.06)' : 'none' }}>
              {/* Turn header */}
              <div style={{
                padding: '4px 10px', fontSize: 9,
                background: isClient ? 'rgba(63,185,80,.08)' : 'rgba(88,166,255,.08)',
                color: 'var(--txD)', display: 'flex', gap: 8, alignItems: 'center',
              }}>
                <span style={{ color, fontWeight: 600 }}>{arrow}</span>
                <span>{turn.srcIp}:{turn.srcPort} → {turn.dstIp}:{turn.dstPort}</span>
                <span style={{ marginLeft: 'auto' }}>{fN(turn.bytes)}B · {turn.packets} pkt{turn.packets > 1 ? 's' : ''}</span>
              </div>
              {/* Payload */}
              <pre style={{
                margin: 0, padding: '6px 10px', color, background: bgColor,
                whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 300, overflowY: 'auto',
              }}>
                {content || '(empty)'}
              </pre>
            </div>
          );
        })}
      </div>

      <div style={{ fontSize: 9, color: 'var(--txD)', marginTop: 6 }}>
        Showing first 128 bytes per packet. Full stream reassembly available with database backend.
      </div>
    </div>
  );
}

export default function SessionDetail({ session: s, onBack, pColors, onTabChange, siblings = [], onNavigate, annotations = [], onSaveNote, collapseStates }) {
  const [tab, setTab] = useState('overview');
  const [pkts, setPkts] = useState([]);
  const [ld, setLd] = useState(false);
  const [showHex, setShowHex] = useState(false);
  const [noteText, setNoteText] = useState('');
  const [noteSaved, setNoteSaved] = useState(false);

  // Collapse state persistence: reads/writes to collapseStatesRef keyed by session ID
  // Each entry is a Map<title, boolean> tracking explicitly toggled sections.
  // Sections not in the map fall back to their component `open` prop default.
  const csRef = collapseStates;
  const lastSessionIdRef = useRef(null);
  const collapseCtx = useMemo(() => {
    if (!csRef?.current) return null;
    const map = csRef.current;
    if (!map.has(s.id)) {
      // New session: clone collapse state from the previous session so all sections keep their state
      const prev = lastSessionIdRef.current && map.has(lastSessionIdRef.current)
        ? new Map(map.get(lastSessionIdRef.current))
        : new Map();
      map.set(s.id, prev);
    }
    lastSessionIdRef.current = s.id;
    const state = map.get(s.id);
    return {
      state,
      toggle: (title, open) => {
        state.set(title, open);
        // Force re-render — we mutate the Map so React doesn't see a change
        setCollapseRender(c => c + 1);
      },
    };
  }, [s.id, csRef]);
  const [, setCollapseRender] = useState(0);

  // Protocol sections (auto-discovered from session_sections/), split by layer
  const _l2Sections     = useMemo(() => _allSections.filter(sec => sec.hasData(s) && sec.layer === 'Link (L2)'), [s]);
  const _l3Sections     = useMemo(() => _allSections.filter(sec => sec.hasData(s) && sec.layer === 'Network (L3)'), [s]);
  const _activeSections = useMemo(() => _allSections.filter(sec => sec.hasData(s) && !sec.layer), [s]);
  const _unclaimedEntries = useMemo(() => [...getUnclaimedPrefixes(s, _allSections).entries()], [s]);

  // Load note for this session
  const existingNote = annotations.find(a => a.annotation_type === 'note' && a.session_id === s.id);
  useEffect(() => {
    setNoteText(existingNote?.text || '');
    setNoteSaved(false);
    // Auto-open Notes collapse if there's existing text
    if (existingNote?.text && csRef?.current) {
      const map = csRef.current;
      if (!map.has(s.id)) map.set(s.id, new Map());
      map.get(s.id).set('Notes', true);
    }
  }, [s.id, annotations]);
  const saveNote = useCallback(async () => {
    if (onSaveNote) {
      await onSaveNote(s.id, noteText, existingNote?.id, 'session_id');
      setNoteSaved(true);
      setTimeout(() => setNoteSaved(false), 1500);
    }
  }, [s.id, noteText, existingNote, onSaveNote]);

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
    if (tab === 'packets' || tab === 'payload' || tab === 'stream') loadP();
  }, [tab, loadP]);

  return (
    <CollapseContext.Provider value={collapseCtx}>
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
        {(['overview', ...(s.source_type ? [] : ['packets', 'payload', 'stream', 'charts'])]).map(t => (
          <button key={t} className={'btn' + (tab === t ? ' on' : '')}
            onClick={() => switchTab(t)} style={{ textTransform: 'uppercase', letterSpacing: '.05em', fontSize: 9 }}>{t}</button>
        ))}
      </div>

      {tab === 'overview' && (
        <div>
          {/* ═══════════════ GENERAL ═══════════════ */}
          <div className="sd-metrics">
            <div className="sd-metric"><div className="sd-metric-val">{fN(s.packet_count)}</div><div className="sd-metric-lbl">Packets</div></div>
            <div className="sd-metric"><div className="sd-metric-val">{fB(s.total_bytes)}</div><div className="sd-metric-lbl">Total bytes</div></div>
            <div className="sd-metric"><div className="sd-metric-val">{fD(s.duration)}</div><div className="sd-metric-lbl">Duration</div></div>
          </div>
          {s.initiator_ip && <Row l="Initiator" v={s.initiator_ip + ':' + s.initiator_port} />}
          {s.responder_ip && <Row l="Responder" v={s.responder_ip + ':' + s.responder_port} />}

          <Collapse title="Directional Traffic" card={false}>
            <div className="sd-dir">
              <div className="sd-dir-lbl"><span style={{ color: 'var(--acG)' }}>→</span> Initiator sent</div>
              <div className="sd-dir-val">{fN(s.fwd_packets)} pkts <span style={{ color: 'var(--txD)', fontWeight: 400 }}>/</span> {fB(s.fwd_bytes)}</div>
            </div>
            {s.fwd_payload_bytes > 0 && (
              <div className="sd-dir" style={{ paddingLeft: 20 }}>
                <div className="sd-dir-lbl">payload</div>
                <div className="sd-dir-val">{fB(s.fwd_payload_bytes)}</div>
              </div>
            )}
            <div className="sd-dir">
              <div className="sd-dir-lbl"><span style={{ color: 'var(--ac)' }}>←</span> Responder sent</div>
              <div className="sd-dir-val">{fN(s.rev_packets)} pkts <span style={{ color: 'var(--txD)', fontWeight: 400 }}>/</span> {fB(s.rev_bytes)}</div>
            </div>
            {s.rev_payload_bytes > 0 && (
              <div className="sd-dir" style={{ paddingLeft: 20 }}>
                <div className="sd-dir-lbl">payload</div>
                <div className="sd-dir-val">{fB(s.rev_payload_bytes)}</div>
              </div>
            )}
          </Collapse>

          {/* ═══════════════ LINK (L2) ═══════════════ */}
          {_l2Sections.length > 0 && (
            <Collapse title="Link (L2)" level="layer">
              {_l2Sections.map(sec => (
                <Collapse key={sec.id} title={sec.title(s)} open={sec.defaultOpen}>
                  <sec.Component s={s} />
                </Collapse>
              ))}
            </Collapse>
          )}

          {/* ═══════════════ NETWORK (L3) ═══════════════ */}
          {(!s.source_type || _l3Sections.length > 0) && (
          <Collapse title="Network (L3)" level="layer">

          {(s.ttls_initiator?.length > 0 || s.ttls_responder?.length > 0) && (
            <Collapse title="TTL">
              {s.ttls_initiator?.length > 0 && <Row l="Initiator TTL" v={s.ttls_initiator.join(', ')} />}
              {s.ttls_responder?.length > 0 && <Row l="Responder TTL" v={s.ttls_responder.join(', ')} />}
            </Collapse>
          )}

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

          {_l3Sections.map(sec => (
            <Collapse key={sec.id} title={sec.title(s)} open={sec.defaultOpen}>
              <sec.Component s={s} />
            </Collapse>
          ))}

          </Collapse>
          )}

          {/* ═══════════════ TRANSPORT (L4) ═══════════════ */}
          {s.transport === 'TCP' && !s.source_type && (
            <Collapse title="Transport (L4)" level="layer">

              {(s.initiator_ports?.length > 0 || s.responder_ports?.length > 0) && (
                <Collapse title="Ports">
                  {s.initiator_ports?.length > 0 && (
                    <Row l="Initiator →" v={s.initiator_ports.slice(0, 10).join(', ') + (s.initiator_ports.length > 10 ? '…' : '')} />
                  )}
                  {s.responder_ports?.length > 0 && (
                    <Row l="Responder →" v={s.responder_ports.slice(0, 10).join(', ') + (s.responder_ports.length > 10 ? '…' : '')} />
                  )}
                </Collapse>
              )}

              {((s.retransmits_fwd > 0 || s.retransmits_rev > 0 || s.out_of_order_fwd > 0 || s.out_of_order_rev > 0)) && (
                <Collapse title="TCP Reliability">
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

              {(s.window_min > 0 || s.init_window_initiator > 0) && (
                <Collapse title="Window Size">
                  {s.init_window_initiator > 0 && <Row l="Init (initiator →)" v={fN(s.init_window_initiator)} />}
                  {s.init_window_responder > 0 && <Row l="Init (responder →)" v={fN(s.init_window_responder)} />}
                  {s.window_min > 0 && <Row l="Min / Max" v={fN(s.window_min) + ' / ' + fN(s.window_max)} />}
                </Collapse>
              )}

              {Object.keys(s.flag_counts || {}).some(k => (s.flag_counts || {})[k] > 0) && (
                <Collapse title="TCP Flags">
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4 }}>
                    {Object.entries(s.flag_counts || {}).filter(([, v]) => v > 0).map(([f, c]) => (
                      <div key={f} style={{
                        background: 'var(--bg)', border: '1px solid var(--bgH)',
                        borderRadius: 6, padding: '6px 10px',
                        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      }}>
                        <FlagBadge f={f} />
                        <span style={{ fontSize: 12, fontWeight: 600, fontFamily: 'var(--fd)' }}>{c}</span>
                      </div>
                    ))}
                  </div>
                </Collapse>
              )}

              {s.seq_first > 0 && (
                <Collapse title="Seq / Ack">
                  <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 6 }}>Use CHARTS tab for visual view</div>
                  <div className="sd-seq-grid">
                    {s.seq_isn_init > 0 && <div className="sd-seq-cell"><div className="sd-seq-lbl">ISN initiator</div><div className="sd-seq-val">{fN(s.seq_isn_init)}</div></div>}
                    {s.seq_isn_resp > 0 && <div className="sd-seq-cell"><div className="sd-seq-lbl">ISN responder</div><div className="sd-seq-val">{fN(s.seq_isn_resp)}</div></div>}
                    <div className="sd-seq-cell"><div className="sd-seq-lbl">First seq</div><div className="sd-seq-val">{fN(s.seq_first)}</div></div>
                    <div className="sd-seq-cell"><div className="sd-seq-lbl">Last seq</div><div className="sd-seq-val">{fN(s.seq_last)}</div></div>
                    <div className="sd-seq-cell"><div className="sd-seq-lbl">First ack</div><div className="sd-seq-val">{fN(s.ack_first)}</div></div>
                    <div className="sd-seq-cell"><div className="sd-seq-lbl">Last ack</div><div className="sd-seq-val">{fN(s.ack_last)}</div></div>
                  </div>
                </Collapse>
              )}

              {s.tcp_options_seen?.length > 0 && (
                <Collapse title="TCP Options">
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    {s.tcp_options_seen.map(o => <Tag key={o} color="#bc8cff">{o}</Tag>)}
                  </div>
                </Collapse>
              )}
            </Collapse>
          )}

          {/* UDP — show ports under transport header */}
          {s.transport === 'UDP' && (s.initiator_ports?.length > 0 || s.responder_ports?.length > 0) && (
            <Collapse title="Transport (L4)" level="layer">
              <Collapse title="Ports">
                {s.initiator_ports?.length > 0 && (
                  <Row l="Initiator →" v={s.initiator_ports.slice(0, 10).join(', ') + (s.initiator_ports.length > 10 ? '…' : '')} />
                )}
                {s.responder_ports?.length > 0 && (
                  <Row l="Responder →" v={s.responder_ports.slice(0, 10).join(', ') + (s.responder_ports.length > 10 ? '…' : '')} />
                )}
              </Collapse>
            </Collapse>
          )}

          {/* ═══════════════ ZEEK CONNECTION ═══════════════ */}
          {s.source_type === 'zeek' && (s.zeek_conn_state || s.zeek_history || s.zeek_duration != null || s.zeek_service) && (
            <Collapse title="Connection (Zeek)" level="layer">
              {s.zeek_conn_state && (() => {
                const desc = {
                  S0: 'SYN sent, no reply',
                  S1: 'SYN-ACK seen, connection established (no data)',
                  SF: 'Normal — established and closed cleanly',
                  REJ: 'Connection rejected (RST to SYN)',
                  S2: 'Established, initiator closed (no responder close)',
                  S3: 'Established, responder closed (no initiator close)',
                  RSTO: 'Established, initiator aborted (RST)',
                  RSTR: 'Established, responder aborted (RST)',
                  RSTOS0: 'Initiator sent SYN then RST (no SYN-ACK)',
                  RSTRH: 'Responder sent RST (no SYN)',
                  SH: 'Initiator sent SYN+FIN, no responder reply',
                  SHR: 'Initiator sent SYN+FIN, responder sent RST',
                  OTH: 'Midstream traffic (no SYN, no RST)',
                };
                return <Row l="Conn State" v={`${s.zeek_conn_state}${desc[s.zeek_conn_state] ? ' — ' + desc[s.zeek_conn_state] : ''}`} />;
              })()}
              {s.zeek_history && <Row l="History" v={s.zeek_history} />}
              {s.zeek_duration != null && <Row l="Duration" v={`${s.zeek_duration.toFixed(3)}s`} />}
              {s.zeek_service && <Row l="Service" v={s.zeek_service} />}
              {s.zeek_uid && <Row l="UID" v={s.zeek_uid} />}
            </Collapse>
          )}

          {/* ═══════════════ APPLICATION (L5+) ═══════════════ */}
          {(_activeSections.length > 0 || _unclaimedEntries.length > 0) && (
            <Collapse title="Application (L5+)" level="layer">
              {_activeSections.map(sec => (
                <Collapse key={sec.id} title={sec.title(s)} open={sec.defaultOpen}>
                  <sec.Component s={s} />
                </Collapse>
              ))}
              {_unclaimedEntries.map(([prefix, keys]) => (
                <FallbackSection key={prefix} s={s} prefix={prefix} keys={keys} />
              ))}
            </Collapse>
          )}

          {/* ═══════════════ ADVANCED ═══════════════ */}
          <Collapse title="Advanced">
            <Row l="Session ID" v={sessionRefHash(s)} />
            {s.source_type && <Row l="Source" v={s.source_type} />}
            {s.start_time > 0 && <Row l="Start time" v={new Date(s.start_time * 1000).toISOString()} />}
            {s.end_time > 0 && <Row l="End time" v={new Date(s.end_time * 1000).toISOString()} />}
            <div style={{ marginTop: 6, fontSize: 9, color: 'var(--txD)' }}>
              Internal key: <span style={{ fontFamily: 'var(--fn)', wordBreak: 'break-all' }}>{s.id}</span>
            </div>
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
                  {/* Entropy badge */}
                  {p.payload_entropy?.value != null && (() => {
                    const e = p.payload_entropy;
                    const col = e.value >= 7.5 ? '#f85149' : e.value >= 6.5 ? '#d29922' : e.value >= 5.0 ? '#58a6ff' : e.value >= 3.5 ? '#3fb950' : '#8b949e';
                    return (
                      <span title={e.label + ' (' + e.byte_count + ' bytes)'} style={{
                        fontSize: 8, padding: '0 5px', borderRadius: 6, lineHeight: '15px', flexShrink: 0,
                        background: col + '18', color: col, border: '1px solid ' + col + '30',
                        fontFamily: 'var(--fn)',
                      }}>H={e.value} {e.label}</span>
                    );
                  })()}
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

      {tab === 'stream' && (
        <StreamView pkts={pkts} session={s} loading={ld} />
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

      {/* Notes — always visible below all tabs */}
      <Collapse title="Notes" open={!!noteText}>
        <textarea
          value={noteText}
          onChange={e => setNoteText(e.target.value)}
          placeholder="Add investigation notes…"
          rows={3}
          style={{
            width: '100%', boxSizing: 'border-box',
            background: 'var(--bg)', border: '1px solid var(--bgH)', borderRadius: 4,
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
    </CollapseContext.Provider>
  );
}
