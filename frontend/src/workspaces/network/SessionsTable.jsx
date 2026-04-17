import React, { useState, useMemo, useEffect, useRef, useCallback } from 'react';
import { FixedSizeList } from 'react-window';
import Tag from '../../components/Tag';
import { fN, fB, fD } from '../../utils';
import { fetchSessions } from '../../api';

export default function SessionsTable({ sessions: globalSessions, pColors, onSelect }) {
  const [sortBy, setSortBy]         = useState('bytes');
  const [localSearch, setLocalSearch] = useState('');
  const [localSessions, setLocalSessions] = useState(null); // null = use globalSessions
  const [localTotal, setLocalTotal] = useState(0);
  const [localLoading, setLocalLoading] = useState(false);
  const debounceRef = useRef(null);

  // When localSearch changes, re-fetch sessions independently of the graph search.
  // On clear, revert to globalSessions.
  useEffect(() => {
    clearTimeout(debounceRef.current);
    if (!localSearch.trim()) {
      setLocalSessions(null);
      setLocalTotal(0);
      return;
    }
    debounceRef.current = setTimeout(async () => {
      setLocalLoading(true);
      try {
        const d = await fetchSessions(1000, localSearch.trim());
        setLocalSessions(d.sessions || []);
        setLocalTotal(d.total ?? d.sessions?.length ?? 0);
      } catch (e) {
        console.error('Local session search error:', e);
      } finally {
        setLocalLoading(false);
      }
    }, 250);
    return () => clearTimeout(debounceRef.current);
  }, [localSearch]);

  const sessions = localSessions ?? globalSessions;

  const sorted = useMemo(() => {
    let s = [...sessions];
    if (sortBy === 'packets') s.sort((a, b) => b.packet_count - a.packet_count);
    else if (sortBy === 'duration') s.sort((a, b) => b.duration - a.duration);
    else if (sortBy === 'time') s.sort((a, b) => (a.start_time || 0) - (b.start_time || 0));
    return s;
  }, [sessions, sortBy]);

  const countLabel = localSearch && localSessions
    ? `${fN(localSessions.length)}/${fN(localTotal)}`
    : fN(sessions.length);

  // Virtual list height — tracks the flex-1 container via ResizeObserver
  const listContainerRef = useRef(null);
  const [listHeight, setListHeight] = useState(400);
  useEffect(() => {
    const el = listContainerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => setListHeight(entry.contentRect.height));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const renderRow = useCallback(({ index, style }) => {
    const s = sorted[index];
    return (
      <div style={{ ...style, paddingLeft: 16, paddingRight: 16 }}>
        <div className="hr" onClick={() => onSelect(s)}
          style={{ padding: '8px 6px', borderBottom: '1px solid var(--bd)', cursor: 'pointer', borderRadius: 3, transition: 'background .15s' }}>
          <div style={{ fontSize: 11 }}>
            {s.initiator_ip ? (
              <><span style={{ color: 'var(--acG)' }}>{s.initiator_ip}:{s.initiator_port}</span> → {s.responder_ip}:{s.responder_port}</>
            ) : (
              <>{s.src_ip}:{s.src_port} ↔ {s.dst_ip}:{s.dst_port}</>
            )}
          </div>
          <div style={{ display: 'flex', gap: 4, marginTop: 4, alignItems: 'center', flexWrap: 'wrap' }}>
            <Tag color={pColors[s.protocol] || '#64748b'} small>{s.protocol}</Tag>
            <span style={{ fontSize: 10, color: 'var(--txM)' }}>{fN(s.packet_count)} pkts</span>
            <span style={{ fontSize: 10, color: 'var(--txM)' }}>{fB(s.total_bytes)}</span>
            <span style={{ fontSize: 10, color: 'var(--txD)' }}>{fD(s.duration)}</span>
            {s.has_handshake && <Tag color="#3fb950" small tip="TCP Handshake completed (SYN→SYN+ACK→ACK)">HS</Tag>}
            {s.has_reset && <Tag color="#f85149" small tip="Connection reset (abrupt termination)">RST</Tag>}
            {s.has_fin && <Tag color="#d29922" small tip="Connection finished (graceful close)">FIN</Tag>}
          </div>
        </div>
      </div>
    );
  }, [sorted, pColors, onSelect]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Fixed header */}
      <div style={{ padding: '12px 16px 8px', flexShrink: 0 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
          <div className="sh" style={{ marginBottom: 0 }}>
            Sessions ({countLabel})
            {localLoading && <span style={{ color: 'var(--txD)', fontSize: 9, marginLeft: 6 }}>…</span>}
          </div>
          <div style={{ display: 'flex', gap: 3 }}>
            {['bytes', 'packets', 'duration', 'time'].map(s => (
              <button key={s} className={'btn' + (sortBy === s ? ' on' : '')}
                onClick={() => setSortBy(s)} style={{ padding: '2px 8px', fontSize: 9 }}>{s}</button>
            ))}
          </div>
        </div>
        {/* Local search — filters sessions independently of the graph */}
        <div style={{ position: 'relative' }}>
          <svg style={{ position: 'absolute', left: 7, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }}
            width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--txD)" strokeWidth="2">
            <circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
          </svg>
          <input className="inp" placeholder="Filter sessions…"
            value={localSearch} onChange={e => setLocalSearch(e.target.value)}
            style={{ width: '100%', paddingLeft: 24, fontSize: 10, boxSizing: 'border-box' }} />
          {localSearch && (
            <button onClick={() => setLocalSearch('')} style={{
              position: 'absolute', right: 6, top: '50%', transform: 'translateY(-50%)',
              background: 'none', border: 'none', cursor: 'pointer', color: 'var(--txD)', fontSize: 12, lineHeight: 1,
            }}>✕</button>
          )}
        </div>
      </div>
      {/* Virtualized list — only renders visible rows (react-window) */}
      <div ref={listContainerRef} style={{ flex: 1, minHeight: 0 }}>
        <FixedSizeList
          height={listHeight}
          width="100%"
          itemCount={sorted.length}
          itemSize={65}
          style={{ overflowX: 'hidden' }}
        >
          {renderRow}
        </FixedSizeList>
      </div>
    </div>
  );
}
