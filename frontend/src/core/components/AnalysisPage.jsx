import React, { useState, useMemo, useEffect } from 'react';
import { VERSION } from '../../version.js';
import { fetchAnalysisResults } from '../api';
import { fB, fN } from '../utils';
import LLMInterpretationPanel from './LLMInterpretationPanel';

// ── Centrality computation (client-side, operates on currently-visible nodes/edges) ─
// Runs on the filtered graph that App.jsx passes in — so time range, protocol filter,
// and display filter are all respected. This is intentional: HTTP centrality and
// Kerberos centrality are completely different graphs.

function computeCentrality(nodes, edges) {
  if (!nodes?.length || !edges?.length) return [];
  const nodeIds = new Set(nodes.map(n => n.id));
  const adj = new Map();
  nodes.forEach(n => adj.set(n.id, new Set()));
  edges.forEach(e => {
    const s = e.source?.id ?? e.source;
    const t = e.target?.id ?? e.target;
    if (!nodeIds.has(s) || !nodeIds.has(t)) return;
    adj.get(s)?.add(t); adj.get(t)?.add(s);
  });
  const betweenness = new Map();
  nodes.forEach(n => betweenness.set(n.id, 0));
  for (const src of nodes) {
    const stack=[], pred=new Map(), sigma=new Map(), dist=new Map();
    nodes.forEach(n => { pred.set(n.id,[]); sigma.set(n.id,0); dist.set(n.id,-1); });
    sigma.set(src.id,1); dist.set(src.id,0);
    const queue=[src.id];
    while(queue.length){
      const v=queue.shift(); stack.push(v);
      for(const w of(adj.get(v)||[])){
        if(dist.get(w)<0){queue.push(w);dist.set(w,dist.get(v)+1);}
        if(dist.get(w)===dist.get(v)+1){sigma.set(w,sigma.get(w)+sigma.get(v));pred.get(w).push(v);}
      }
    }
    const delta=new Map(); nodes.forEach(n=>delta.set(n.id,0));
    while(stack.length){
      const w=stack.pop();
      for(const v of(pred.get(w)||[])) delta.set(v,delta.get(v)+(sigma.get(v)/sigma.get(w))*(1+delta.get(w)));
      if(w!==src.id) betweenness.set(w,betweenness.get(w)+delta.get(w));
    }
  }
  const n=nodes.length, normB=Math.max(1,(n-1)*(n-2)/2);
  const maxDeg=Math.max(1,n-1), maxBytes=Math.max(1,...nodes.map(nd=>nd.total_bytes||0));
  const maxBtw=Math.max(1,...Array.from(betweenness.values()));
  return nodes.map(nd=>{
    const deg=adj.get(nd.id)?.size||0;
    const btw=betweenness.get(nd.id)/normB;
    const byt=(nd.total_bytes||0)/maxBytes;
    return {
      id:nd.id, label:nd.metadata?.name||nd.hostnames?.[0]||nd.id,
      degree:deg, degreeNorm:deg/maxDeg,
      betweennessNorm:btw/(maxBtw/normB), bytesNorm:byt,
      totalBytes:nd.total_bytes||0,
      score:(deg/maxDeg+betweenness.get(nd.id)/maxBtw+byt)/3,
      ips: nd.ips || [nd.id],
    };
  }).sort((a,b)=>b.score-a.score);
}

function Bar({ value, color }) {
  return (
    <div style={{ height: 4, background: 'var(--bgH)', borderRadius: 2, overflow: 'hidden', width: 72, flexShrink: 0 }}>
      <div style={{ height: '100%', width: `${Math.round(Math.min(1, value) * 100)}%`, background: color, borderRadius: 2 }} />
    </div>
  );
}

// ── Shared IP/session search bar ─────────────────────────────────────────────

function SearchBar({ onSearch, placeholder }) {
  const [ip1, setIp1] = useState('');
  const [ip2, setIp2] = useState('');
  const [showIp2, setShowIp2] = useState(false);

  function fire() { onSearch({ ip1: ip1.trim(), ip2: ip2.trim() }); }
  function clear() { setIp1(''); setIp2(''); setShowIp2(false); onSearch({ ip1: '', ip2: '' }); }

  return (
    <div style={{ display: 'flex', gap: 5, alignItems: 'center', flexShrink: 0, flexWrap: 'wrap', marginBottom: 8 }}>
      <input
        className="inp" placeholder={placeholder || 'Filter by IP…'}
        value={ip1} onChange={e => setIp1(e.target.value)}
        onKeyDown={e => e.key === 'Enter' && fire()}
        style={{ width: 140, fontSize: 10, padding: '3px 8px' }}
      />
      {showIp2 && (
        <input
          className="inp" placeholder="Second IP (optional)"
          value={ip2} onChange={e => setIp2(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && fire()}
          style={{ width: 140, fontSize: 10, padding: '3px 8px' }}
        />
      )}
      <button className="btn" onClick={() => setShowIp2(v => !v)}
        style={{ fontSize: 9, padding: '2px 7px', opacity: showIp2 ? 1 : 0.6 }}>
        {showIp2 ? '− 2nd IP' : '+ 2nd IP'}
      </button>
      <button className="btn on" onClick={fire} style={{ fontSize: 9, padding: '2px 8px' }}>Search</button>
      {(ip1 || ip2) && <button className="btn" onClick={clear} style={{ fontSize: 9, padding: '2px 6px' }}>✕</button>}
    </div>
  );
}

// ── Node Centrality panel ────────────────────────────────────────────────────

function NodeCentralityPanel({ nodes, edges, onSelectNode }) {
  // ranked: computed from the currently-visible filtered graph (respects time range + protocol filter)
  const ranked = useMemo(() => computeCentrality(nodes, edges).map((r, i) => ({ ...r, globalRank: i + 1 })), [nodes, edges]);
  const [sortBy, setSortBy] = useState('score');
  const [limit, setLimit] = useState(20);
  const [search, setSearch] = useState({ ip1: '', ip2: '' });

  // filtering preserves globalRank; re-sort by selected column
  const filtered = useMemo(() => {
    let r = [...ranked];
    if (search.ip1) r = r.filter(row => row.ips.some(ip => ip.includes(search.ip1)));
    if (search.ip2) r = r.filter(row => row.ips.some(ip => ip.includes(search.ip2)));
    r.sort((a, b) => b[sortBy] - a[sortBy]);
    return r.slice(0, limit);
  }, [ranked, search, sortBy, limit]);

  const isFiltered = !!(search.ip1 || search.ip2);
  const matchCount = useMemo(() => {
    let r = ranked;
    if (search.ip1) r = r.filter(row => row.ips.some(ip => ip.includes(search.ip1)));
    if (search.ip2) r = r.filter(row => row.ips.some(ip => ip.includes(search.ip2)));
    return r.length;
  }, [ranked, search]);

  if (!ranked.length) return <div style={{ color: 'var(--txD)', fontSize: 12, padding: 8 }}>No graph data loaded.</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      <SearchBar onSearch={setSearch} placeholder="Filter by IP…" />
      <div style={{ display: 'flex', gap: 5, alignItems: 'center', marginBottom: 8, flexShrink: 0, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em' }}>Sort</span>
        {[
          { key: 'score', label: 'Score', tip: 'Composite: degree + betweenness + traffic (equal thirds)' },
          { key: 'degree', label: 'Degree', tip: 'Unique direct peers' },
          { key: 'betweennessNorm', label: 'Betweenness', tip: 'Bridge score: how often on shortest paths' },
          { key: 'bytesNorm', label: 'Traffic', tip: 'Total bytes as fraction of top node' },
        ].map(col => (
          <button key={col.key} className={'btn' + (sortBy === col.key ? ' on' : '')}
            onClick={() => setSortBy(col.key)} title={col.tip}
            style={{ fontSize: 9, padding: '2px 7px' }}>{col.label}</button>
        ))}
        <div style={{ flex: 1 }} />
        {[10, 20, 50].map(l => (
          <button key={l} className={'btn' + (limit === l ? ' on' : '')}
            onClick={() => setLimit(l)} style={{ fontSize: 9, padding: '2px 6px' }}>{l}</button>
        ))}
      </div>
      <div style={{ overflowY: 'auto', flex: 1 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--bd)' }}>
              {['#', 'Node', 'Score', 'Degree', 'Betweenness', 'Traffic'].map(h => (
                <th key={h} style={{ textAlign: h === '#' || h === 'Node' ? 'left' : 'center', padding: '4px 8px', color: 'var(--txD)', fontWeight: 500, fontSize: 9, textTransform: 'uppercase' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((row) => (
              <tr key={row.id} className="hr" onClick={() => onSelectNode?.(row.id)}
                style={{ borderBottom: '1px solid var(--bd)', cursor: 'pointer' }}>
                <td style={{ padding: '5px 8px', color: 'var(--txD)', fontSize: 10, width: 24 }}>
                  {row.globalRank}
                </td>
                <td style={{ padding: '5px 8px', maxWidth: 140 }}>
                  <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--tx)', fontSize: 11 }} title={row.id}>{row.label}</div>
                  <div style={{ fontSize: 9, color: 'var(--txD)' }}>{fB(row.totalBytes)}</div>
                </td>
                <td style={{ padding: '5px 8px', textAlign: 'center' }}>
                  <span style={{ fontSize: 10, color: 'var(--txM)', fontFamily: 'var(--fn)' }}>{(row.score * 100).toFixed(0)}</span>
                </td>
                <td style={{ padding: '5px 8px', textAlign: 'center' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                    <span style={{ fontSize: 10, color: 'var(--txM)' }}>{row.degree}</span>
                    <Bar value={row.degreeNorm} color="#58a6ff" />
                  </div>
                </td>
                <td style={{ padding: '5px 8px', textAlign: 'center' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                    <span style={{ fontSize: 10, color: 'var(--txM)' }}>{(row.betweennessNorm * 100).toFixed(1)}%</span>
                    <Bar value={row.betweennessNorm} color="#2dd4bf" />
                  </div>
                </td>
                <td style={{ padding: '5px 8px', textAlign: 'center' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                    <span style={{ fontSize: 10, color: 'var(--txM)' }}>{fB(row.totalBytes)}</span>
                    <Bar value={row.bytesNorm} color="#f0883e" />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div style={{ fontSize: 9, color: 'var(--txD)', marginTop: 6, flexShrink: 0 }}>
        {filtered.length} of {isFiltered ? matchCount : ranked.length} nodes{isFiltered ? ` (filtered from ${ranked.length})` : ''} · # = global rank · Click row to select on graph
      </div>
    </div>
  );
}

// ── Traffic Characterisation ─────────────────────────────────────────────────

function classifySession(s) {
  const dur = s.duration || 0, pkts = s.packet_count || 0, bytes = s.total_bytes || 0;
  if (!pkts) return { label: 'unknown', fgScore: 0, bgScore: 0, evidence: [] };
  let fg = 0, bg = 0, evidence = [];
  const pps = dur > 0 ? pkts / dur : pkts;
  const bpp = bytes / pkts;

  // ARP is infrastructure/discovery traffic — always background
  if ((s.protocol || '').toUpperCase() === 'ARP') {
    return { label: 'background', fgScore: 0, bgScore: 10, evidence: [{ sig: 'bg', text: 'ARP — address resolution / network discovery, always automated infrastructure traffic' }] };
  }

  if (dur < 2)        { fg += 2; evidence.push({ sig: 'fg', text: `Short session (${dur < 1 ? '<1' : dur.toFixed(1)}s) — typical interactive request` }); }
  else if (dur < 30)  { fg += 1; evidence.push({ sig: 'fg', text: `Medium session (${dur.toFixed(1)}s)` }); }
  else if (dur > 300) { bg += 2; evidence.push({ sig: 'bg', text: `Long-running session (${Math.round(dur)}s) — likely persistent background process` }); }
  else                { bg += 1; evidence.push({ sig: 'bg', text: `Extended session (${Math.round(dur)}s)` }); }

  if (pps > 10)      { fg += 2; evidence.push({ sig: 'fg', text: `High packet rate (${pps.toFixed(1)} pps) — bursty interactive traffic` }); }
  else if (pps > 2)  { fg += 1; evidence.push({ sig: 'fg', text: `Moderate packet rate (${pps.toFixed(1)} pps)` }); }
  else               { bg += 1; evidence.push({ sig: 'bg', text: `Low packet rate (${pps.toFixed(2)} pps) — possibly polling or keepalive` }); }

  if (bpp > 500)     { fg += 1; evidence.push({ sig: 'fg', text: `Large avg packet (${Math.round(bpp)} B) — data transfer` }); }
  else if (bpp < 80) { bg += 2; evidence.push({ sig: 'bg', text: `Tiny avg packet (${Math.round(bpp)} B) — typical beacon or keepalive` }); }

  if (s.has_handshake) { fg += 2; evidence.push({ sig: 'fg', text: 'TCP handshake completed (SYN→SYN+ACK→ACK) — interactive connection' }); }
  if (s.has_reset)     { bg += 1; evidence.push({ sig: 'bg', text: 'TCP RST seen — often automated retry or refused connection' }); }
  if (s.has_fin && dur < 10) { fg += 1; evidence.push({ sig: 'fg', text: 'Clean FIN close on short session — well-behaved interactive flow' }); }

  const label = fg > bg ? 'foreground' : bg > fg ? 'background' : 'ambiguous';
  return { label, fgScore: fg, bgScore: bg, evidence };
}

const LABEL_COLORS = { foreground: '#3fb950', background: '#f0883e', ambiguous: '#8b949e', unknown: '#484f58' };
const LABEL_TIPS = {
  foreground: 'Interactive — short, bursty. Likely a human doing something.',
  background: 'Automated — long-running, tiny packets. Likely a process phoning home.',
  ambiguous: 'Mixed signals.',
};

function EvidenceBadge({ sig, text }) {
  const color = sig === 'fg' ? '#3fb950' : '#f0883e';
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6, padding: '3px 0' }}>
      <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 6, background: color + '22', color, border: `1px solid ${color}44`, flexShrink: 0, marginTop: 1 }}>
        {sig === 'fg' ? '▲ fg' : '▼ bg'}
      </span>
      <span style={{ fontSize: 10, color: 'var(--txM)', lineHeight: 1.5 }}>{text}</span>
    </div>
  );
}

function TrafficRow({ s, pColors }) {
  const [open, setOpen] = useState(false);
  const lbl = s.cls.label;
  const proto = s.protocol || '?';
  const src = s.initiator_ip || s.src_ip || '?';
  const dst = s.responder_ip || s.dst_ip || '?';
  const sP = s.initiator_port ?? s.src_port ?? '';
  const dP = s.responder_port ?? s.dst_port ?? '';

  return (
    <>
      <tr className="hr" onClick={() => setOpen(v => !v)}
        style={{ borderBottom: open ? 'none' : '1px solid var(--bd)', cursor: 'pointer' }}>
        <td style={{ padding: '5px 8px', whiteSpace: 'nowrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ fontSize: 9, color: 'var(--txD)', lineHeight: 1 }}>{open ? '▾' : '▸'}</span>
            <span style={{
              fontSize: 9, padding: '1px 6px', borderRadius: 8, fontWeight: 600,
              background: LABEL_COLORS[lbl] + '22', color: LABEL_COLORS[lbl],
              border: `1px solid ${LABEL_COLORS[lbl]}55`, textTransform: 'capitalize',
            }} title={LABEL_TIPS[lbl]}>{lbl}</span>
          </div>
        </td>
        <td style={{ padding: '5px 8px', maxWidth: 200 }}>
          <div style={{ fontSize: 10, color: 'var(--tx)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            <span style={{ color: pColors?.[proto] || 'var(--txD)', fontSize: 9, marginRight: 4 }}>{proto}</span>
            {src}:{sP} → {dst}:{dP}
          </div>
        </td>
        <td style={{ padding: '5px 8px', textAlign: 'right', color: 'var(--txM)', fontSize: 10 }}>{fN(s.packet_count)}</td>
        <td style={{ padding: '5px 8px', textAlign: 'right', color: 'var(--txM)', fontSize: 10 }}>{fB(s.total_bytes)}</td>
        <td style={{ padding: '5px 8px', textAlign: 'right', color: 'var(--txD)', fontSize: 10 }}>
          {s.duration != null ? (s.duration < 1 ? '<1s' : `${Math.round(s.duration)}s`) : '—'}
        </td>
      </tr>
      {open && (
        <tr style={{ borderBottom: '1px solid var(--bd)' }}>
          <td colSpan={5} style={{ padding: '6px 12px 10px 28px', background: 'var(--bgC)' }}>
            <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '.05em' }}>
              Evidence — fg score: {s.cls.fgScore} · bg score: {s.cls.bgScore}
            </div>
            {s.cls.evidence.map((ev, i) => <EvidenceBadge key={i} sig={ev.sig} text={ev.text} />)}
          </td>
        </tr>
      )}
    </>
  );
}

function TrafficCharPanel({ sessions, pColors }) {
  const [filter, setFilter] = useState('all');
  const [sortBy, setSortBy] = useState('bytes');
  const [limit, setLimit] = useState(50); // default higher; "show all" removes cap
  const [showAll, setShowAll] = useState(false);
  const [search, setSearch] = useState({ ip1: '', ip2: '' });

  const classified = useMemo(() => (sessions || []).map(s => ({ ...s, cls: classifySession(s) })), [sessions]);

  // Total counts (whole capture, ignoring IP filter)
  const totalCounts = useMemo(() => {
    const c = { foreground: 0, background: 0, ambiguous: 0 };
    classified.forEach(s => { if (c[s.cls.label] !== undefined) c[s.cls.label]++; });
    return c;
  }, [classified]);

  // IP-filtered subset (before label filter)
  const ipFiltered = useMemo(() => {
    let r = classified;
    if (search.ip1) {
      const q = search.ip1;
      r = r.filter(s => (s.src_ip||'').includes(q) || (s.dst_ip||'').includes(q) ||
        (s.initiator_ip||'').includes(q) || (s.responder_ip||'').includes(q));
    }
    if (search.ip2) {
      const q = search.ip2;
      r = r.filter(s => (s.src_ip||'').includes(q) || (s.dst_ip||'').includes(q) ||
        (s.initiator_ip||'').includes(q) || (s.responder_ip||'').includes(q));
    }
    return r;
  }, [classified, search]);

  // Filtered counts — reflect the IP filter
  const filteredCounts = useMemo(() => {
    const c = { foreground: 0, background: 0, ambiguous: 0 };
    ipFiltered.forEach(s => { if (c[s.cls.label] !== undefined) c[s.cls.label]++; });
    return c;
  }, [ipFiltered]);

  const isFiltered = !!(search.ip1 || search.ip2);
  const counts = isFiltered ? filteredCounts : totalCounts;

  const rows = useMemo(() => {
    let r = ipFiltered.filter(s => filter === 'all' || s.cls.label === filter);
    if (sortBy === 'bytes')    r.sort((a, b) => (b.total_bytes||0) - (a.total_bytes||0));
    if (sortBy === 'packets')  r.sort((a, b) => (b.packet_count||0) - (a.packet_count||0));
    if (sortBy === 'duration') r.sort((a, b) => (b.duration||0) - (a.duration||0));
    if (sortBy === 'time')     r.sort((a, b) => (a.start_time||0) - (b.start_time||0));
    return showAll ? r : r.slice(0, limit);
  }, [ipFiltered, filter, sortBy, limit, showAll]);

  const matchedTotal = ipFiltered.filter(s => filter === 'all' || s.cls.label === filter).length;

  if (!sessions?.length) return <div style={{ color: 'var(--txD)', fontSize: 12, padding: 8 }}>No session data loaded.</div>;
  const total = classified.length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      <SearchBar onSearch={q => { setSearch(q); setShowAll(false); }} placeholder="Filter by IP (src or dst)…" />
      <div style={{ display: 'flex', gap: 5, alignItems: 'center', marginBottom: 8, flexShrink: 0, flexWrap: 'wrap' }}>
        {['all', 'foreground', 'background', 'ambiguous'].map(lbl => {
          const cnt = lbl === 'all' ? (isFiltered ? ipFiltered.length : total) : (counts[lbl] || 0);
          const base = isFiltered ? ipFiltered.length : total;
          const pct = base > 0 ? Math.round(cnt / base * 100) : 0;
          // Also show global for context when filtered
          const globalCnt = lbl === 'all' ? total : (totalCounts[lbl] || 0);
          return (
            <button key={lbl} className={'btn' + (filter === lbl ? ' on' : '')}
              onClick={() => setFilter(lbl)} title={LABEL_TIPS[lbl]}
              style={{ fontSize: 9, padding: '2px 9px', display: 'flex', alignItems: 'center', gap: 4 }}>
              {lbl !== 'all' && <span style={{ width: 6, height: 6, borderRadius: '50%', background: LABEL_COLORS[lbl], flexShrink: 0 }} />}
              <span style={{ textTransform: 'capitalize' }}>{lbl}</span>
              <span style={{ color: 'var(--txD)' }}>
                {fN(cnt)}{lbl !== 'all' ? ` (${pct}%)` : ''}
                {isFiltered && lbl !== 'all' && <span style={{ color: 'var(--txD)', opacity: 0.5 }}> /{fN(globalCnt)}</span>}
              </span>
            </button>
          );
        })}
        <div style={{ flex: 1 }} />
        {['bytes', 'packets', 'duration'].map(s => (
          <button key={s} className={'btn' + (sortBy === s ? ' on' : '')}
            onClick={() => setSortBy(s)} style={{ fontSize: 9, padding: '2px 7px', textTransform: 'capitalize' }}>{s}</button>
        ))}
      </div>
      <div style={{ display: 'flex', height: 5, borderRadius: 3, overflow: 'hidden', marginBottom: 8, flexShrink: 0, gap: 1 }}>
        {['foreground', 'background', 'ambiguous'].map(lbl => (
          <div key={lbl} style={{ flex: counts[lbl] || 0, background: LABEL_COLORS[lbl], minWidth: counts[lbl] ? 2 : 0 }} title={`${lbl}: ${counts[lbl]}`} />
        ))}
      </div>
      <div style={{ overflowY: 'auto', flex: 1 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--bd)' }}>
              {['Class', 'Session', 'Pkts', 'Bytes', 'Dur'].map((h, idx) => (
                <th key={h} style={{ textAlign: idx <= 1 ? 'left' : 'right', padding: '4px 8px', color: 'var(--txD)', fontWeight: 500, fontSize: 9, textTransform: 'uppercase' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((s, i) => <TrafficRow key={i} s={s} pColors={pColors} />)}
          </tbody>
        </table>
      </div>
      <div style={{ fontSize: 9, color: 'var(--txD)', marginTop: 6, flexShrink: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
        <span>
          {showAll ? matchedTotal : Math.min(rows.length, limit)} of {matchedTotal} sessions
          {isFiltered && ` (filtered from ${total})`}
          {' · Click any row to expand evidence'}
        </span>
        {!showAll && matchedTotal > limit && (
          <button className="btn" onClick={() => setShowAll(true)}
            style={{ fontSize: 9, padding: '1px 7px' }}>
            Show all {matchedTotal}
          </button>
        )}
        {showAll && matchedTotal > 50 && (
          <button className="btn" onClick={() => setShowAll(false)}
            style={{ fontSize: 9, padding: '1px 7px' }}>
            Collapse
          </button>
        )}
      </div>
    </div>
  );
}

// ── Analysis card shell ──────────────────────────────────────────────────────

function AnalysisCard({ icon, title, badge, description, expanded, onToggle, children }) {
  return (
    <div style={{
      background: 'var(--bgC)', border: '1px solid var(--bd)', borderRadius: 10,
      display: 'flex', flexDirection: 'column',
      flex: expanded ? '1 1 0' : '0 0 auto', overflow: 'hidden',
    }}>
      <div onClick={onToggle} style={{
        padding: '14px 18px', borderBottom: expanded ? '1px solid var(--bd)' : 'none',
        display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', flexShrink: 0,
      }}>
        <span style={{ fontSize: 18 }}>{icon}</span>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--tx)' }}>{title}</div>
          {badge && (
            <span style={{
              fontSize: 9, padding: '1px 6px', borderRadius: 8, letterSpacing: '.05em',
              background: 'rgba(63,185,80,.1)', color: 'var(--acG)', border: '1px solid rgba(63,185,80,.3)',
            }}>{badge}</span>
          )}
        </div>
        {!expanded && description && (
          <div style={{ fontSize: 10, color: 'var(--txD)', maxWidth: 260, lineHeight: 1.5 }}>{description}</div>
        )}
        <button className="btn" style={{ fontSize: 9, padding: '2px 8px', flexShrink: 0 }}>
          {expanded ? '↙ Collapse' : '↗ Expand'}
        </button>
      </div>
      {expanded && (
        <div style={{ flex: 1, padding: '14px 18px', overflow: 'hidden', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
          {children}
        </div>
      )}
    </div>
  );
}

// ── Main page ────────────────────────────────────────────────────────────────

export default function AnalysisPage({ nodes, edges, sessions, pColors, onSelectNode, filters, selection }) {
  const [expanded, setExpanded] = useState(null);
  const toggle = key => setExpanded(prev => prev === key ? null : key);
  const anyExpanded = expanded !== null;

  // Fetch additional backend analyses (beyond the two built-in ones)
  const [extraAnalyses, setExtraAnalyses] = useState({});
  useEffect(() => {
    fetchAnalysisResults().then(d => {
      const results = d.results || {};
      // Filter out built-in analyses that have dedicated UI
      const extra = {};
      for (const [name, result] of Object.entries(results)) {
        if (name !== 'node_centrality' && name !== 'traffic_characterisation') {
          extra[name] = result;
        }
      }
      setExtraAnalyses(extra);
    }).catch(() => {});
  }, []);

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, overflowY: 'auto', padding: '24px 32px', background: 'var(--bg)' }}>
      <div style={{ marginBottom: 22, flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
          <div style={{ fontSize: 22, fontWeight: 700, fontFamily: 'var(--fd)', color: 'var(--tx)' }}>Analysis</div>
          <span style={{ fontSize: 9, padding: '2px 8px', borderRadius: 8, letterSpacing: '.06em', background: 'rgba(188,140,255,.12)', color: 'var(--acP)', border: '1px solid rgba(188,140,255,.3)' }}>v{VERSION}</span>
        </div>
        <div style={{ fontSize: 12, color: 'var(--txM)', lineHeight: 1.6, maxWidth: 600 }}>
          Computed from your loaded capture. Node Centrality and Traffic Characterisation have dedicated panels.
          Additional analyses added by researchers render automatically below. Click a panel to expand it.
        </div>
      </div>

      <div style={{
        display: 'flex', gap: 16, marginBottom: 24, flexShrink: 0,
        flexWrap: anyExpanded ? 'nowrap' : 'wrap',
        height: anyExpanded ? 520 : 'auto',
        alignItems: 'stretch',
      }}>
        <AnalysisCard icon="🔗" title="Node Centrality" badge="LIVE"
          description="Ranks nodes by degree, betweenness, and traffic volume."
          expanded={expanded === 'centrality'} onToggle={() => toggle('centrality')}>
          <NodeCentralityPanel nodes={nodes} edges={edges}
            onSelectNode={id => { onSelectNode?.(id); toggle('centrality'); }} />
        </AnalysisCard>

        <AnalysisCard icon="⚡" title="Traffic Characterisation" badge="LIVE"
          description="Classifies sessions as foreground / background / ambiguous. Click any row for evidence."
          expanded={expanded === 'traffic'} onToggle={() => toggle('traffic')}>
          <TrafficCharPanel sessions={sessions} pColors={pColors} />
        </AnalysisCard>
      </div>

      {/* Additional backend analyses — rendered generically from _display */}
      {Object.keys(extraAnalyses).length > 0 && (
        <div style={{ display: 'flex', gap: 16, marginBottom: 24, flexShrink: 0, flexWrap: 'wrap' }}>
          {Object.entries(extraAnalyses).map(([name, result]) => (
            <AnalysisCard key={name} icon={result.icon || '📊'} title={result.title || name}
              badge={result.badge || 'LIVE'} description={result.description || ''}
              expanded={expanded === name} onToggle={() => toggle(name)}>
              {result.data?.error ? (
                <div style={{ color: 'var(--acR)', fontSize: 11 }}>Error: {result.data.error}</div>
              ) : (result.data?._display || []).map((el, i) => {
                if (el.type === 'text') return <div key={i} style={{ fontSize: 11, color: el.color || 'var(--txD)', padding: '4px 0', lineHeight: 1.6 }}>{el.value}</div>;
                if (el.type === 'table') return (
                  <div key={i} style={{ overflowX: 'auto', padding: '4px 0' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
                      <thead><tr style={{ borderBottom: '1px solid var(--bd)' }}>{(el.headers || []).map((h, j) => <th key={j} style={{ textAlign: j <= 1 ? 'left' : 'right', padding: '4px 8px', color: 'var(--txD)', fontWeight: 500, fontSize: 9, textTransform: 'uppercase' }}>{h}</th>)}</tr></thead>
                      <tbody>{(el.rows || []).map((row, ri) => <tr key={ri} className="hr" style={{ borderBottom: '1px solid var(--bd)' }}>{row.map((cell, ci) => <td key={ci} style={{ padding: '4px 8px', textAlign: ci <= 1 ? 'left' : 'right', color: 'var(--txM)', fontSize: 11 }} title={cell}>{cell}</td>)}</tr>)}</tbody>
                    </table>
                  </div>
                );
                if (el.type === 'row') return <div key={i} style={{ display: 'flex', gap: 8, padding: '3px 0', fontSize: 11 }}><span style={{ color: 'var(--txD)', minWidth: 100 }}>{el.label}</span><span style={{ color: 'var(--tx)' }}>{el.value}</span></div>;
                return null;
              })}
            </AnalysisCard>
          ))}
        </div>
      )}

      <div style={{ flex: 1, minWidth: 340, maxWidth: 620, minHeight: 420, display: 'flex', flexDirection: 'column' }}>
        <LLMInterpretationPanel
          filters={filters}
          selection={selection}
        />
      </div>
    </div>
  );
}
