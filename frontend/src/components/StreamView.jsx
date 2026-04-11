/**
 * StreamView.jsx — Wireshark-style "Follow TCP Stream" conversation view.
 *
 * Merges consecutive same-direction payloads into turns, color-coded:
 *   Client (initiator) → green text
 *   Server (responder) → blue text
 * Shows ASCII by default with hex/raw toggle. Supports copy.
 *
 * Props: pkts, session, loading
 */

import React, { useState } from 'react';
import { fN } from '../utils';

export default function StreamView({ pkts, session: s, loading }) {
  const [showMode, setShowMode] = useState('ascii'); // 'ascii' | 'hex' | 'raw'

  if (loading) return <div style={{ color: 'var(--txD)', fontSize: 11, padding: 10 }}>Loading…</div>;

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

  const initiatorIp = withPayload[0].src_ip;
  const initiatorPort = withPayload[0].src_port;

  const turns = [];
  let currentTurn = null;

  for (const p of withPayload) {
    const isClient = p.src_ip === initiatorIp && p.src_port === initiatorPort;
    const dir = isClient ? 'client' : 'server';

    let ascii = '';
    let hex = '';
    let raw = '';
    if (p.payload_bytes) {
      raw = p.payload_bytes;
      const bytes = [];
      for (let i = 0; i < raw.length; i += 2) {
        bytes.push(parseInt(raw.substr(i, 2), 16));
      }
      ascii = bytes.map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('');
      hex = raw.match(/.{1,2}/g)?.join(' ') || '';
    }

    if (currentTurn && currentTurn.dir === dir) {
      currentTurn.ascii += ascii;
      currentTurn.hex += (currentTurn.hex ? ' ' : '') + hex;
      currentTurn.raw += raw;
      currentTurn.bytes += p.payload_len || 0;
      currentTurn.packets++;
    } else {
      currentTurn = {
        dir, srcIp: p.src_ip, srcPort: p.src_port, dstIp: p.dst_ip, dstPort: p.dst_port,
        ascii, hex, raw, bytes: p.payload_len || 0, packets: 1, timestamp: p.timestamp,
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
              style={{ fontSize: 9, padding: '2px 6px', textTransform: 'uppercase' }}>
              {m}
            </button>
          ))}
          <button className="btn" onClick={copyAll} style={{ fontSize: 9, padding: '2px 6px' }} title="Copy entire stream">
            Copy
          </button>
        </div>
      </div>

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
              <div style={{
                padding: '4px 10px', fontSize: 9,
                background: isClient ? 'rgba(63,185,80,.08)' : 'rgba(88,166,255,.08)',
                color: 'var(--txD)', display: 'flex', gap: 8, alignItems: 'center',
              }}>
                <span style={{ color, fontWeight: 600 }}>{arrow}</span>
                <span>{turn.srcIp}:{turn.srcPort} → {turn.dstIp}:{turn.dstPort}</span>
                <span style={{ marginLeft: 'auto' }}>{fN(turn.bytes)}B · {turn.packets} pkt{turn.packets > 1 ? 's' : ''}</span>
              </div>
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
