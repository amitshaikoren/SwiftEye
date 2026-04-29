import React, { useMemo } from 'react';
import Tag from './Tag';
import Collapse from './Collapse';
import { PluginSections } from './PluginSection';
import { fN, fB, fD, FLAG_COLORS, FLAG_TIPS, buildProtoTree } from '../utils';

/** Dedicated renderer for tcp_flags — richer than generic */
function TCPFlagsRenderer({ data, onSelectNode }) {
  if (!data?.summary) return null;
  return (
    <>
      {data.summary.filter(s => s.count > 0).map(s => (
        <div key={s.label} style={{ marginBottom: 8 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11, marginBottom: 3 }}>
            <span style={{ fontWeight: 500 }}>{s.label}</span>
            <Tag color={FLAG_COLORS[s.flag?.split('+')[0]] || '#8b949e'} tip={FLAG_TIPS[s.flag?.split('+')[0]]}>{fN(s.count)}</Tag>
          </div>
          {s.senders?.length > 0 && (
            <div style={{ paddingLeft: 8 }}>
              {s.senders.slice(0, 5).map(([ip, cnt]) => (
                <div key={ip} className="hr" onClick={() => onSelectNode && onSelectNode(ip)}
                  style={{
                    display: 'flex', justifyContent: 'space-between', fontSize: 10,
                    padding: '2px 4px', borderBottom: '1px solid var(--bd)', cursor: 'pointer', borderRadius: 3,
                  }}>
                  <span style={{ color: 'var(--txM)' }}>{ip}</span>
                  <span style={{ color: 'var(--txD)' }}>{cnt}×</span>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </>
  );
}

export default function StatsPanel({ stats, pColors, onSelectNode, pluginResults, uiSlots, subgraphInfo }) {
  const tree = useMemo(() => stats ? buildProtoTree(stats) : null, [stats]);
  if (!stats) return null;

  const dedicated = { 'tcp_flags.tcp_flags_detail': TCPFlagsRenderer };

  return (
    <div className="fi" style={{ padding: 16, overflowY: 'auto', height: '100%' }}>
      {subgraphInfo && (
        <div style={{
          background: 'rgba(56,139,253,.08)', border: '1px solid rgba(56,139,253,.25)',
          borderRadius: 6, padding: '8px 10px', marginBottom: 12,
        }}>
          <div style={{ fontSize: 9, color: '#388bfd', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 6 }}>
            Subgraph Focus
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4 }}>
            <div><div style={{ fontSize: 9, color: 'var(--txD)' }}>Nodes</div><div style={{ fontSize: 13, fontWeight: 600, fontFamily: 'var(--fd)', color: 'var(--tx)' }}>{fN(subgraphInfo.nodes)}</div></div>
            <div><div style={{ fontSize: 9, color: 'var(--txD)' }}>Connections</div><div style={{ fontSize: 13, fontWeight: 600, fontFamily: 'var(--fd)', color: 'var(--tx)' }}>{fN(subgraphInfo.connections)}</div></div>
            <div><div style={{ fontSize: 9, color: 'var(--txD)' }}>Bytes</div><div style={{ fontSize: 13, fontWeight: 600, fontFamily: 'var(--fd)', color: 'var(--tx)' }}>{fB(subgraphInfo.bytes)}</div></div>
            <div><div style={{ fontSize: 9, color: 'var(--txD)' }}>Packets</div><div style={{ fontSize: 13, fontWeight: 600, fontFamily: 'var(--fd)', color: 'var(--tx)' }}>{fN(subgraphInfo.packets)}</div></div>
          </div>
        </div>
      )}
      <div className="sh">Overview</div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginBottom: 16 }}>
        <div className="sc"><div style={{ fontSize: 9, color: 'var(--txM)', textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 2 }}>Packets</div><div style={{ fontSize: 17, fontWeight: 600, fontFamily: 'var(--fd)' }}>{fN(stats.total_packets)}</div><div style={{ fontSize: 9, color: 'var(--txD)' }}>{stats.packets_per_second} pps</div></div>
        <div className="sc"><div style={{ fontSize: 9, color: 'var(--txM)', textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 2 }}>Data</div><div style={{ fontSize: 17, fontWeight: 600, fontFamily: 'var(--fd)' }}>{fB(stats.total_bytes)}</div><div style={{ fontSize: 9, color: 'var(--txD)' }}>avg {fB(stats.avg_packet_size)}/pkt</div></div>
        <div className="sc"><div style={{ fontSize: 9, color: 'var(--txM)', textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 2 }}>Endpoints</div><div style={{ fontSize: 17, fontWeight: 600, fontFamily: 'var(--fd)' }}>{stats.unique_ips}</div><div style={{ fontSize: 9, color: 'var(--txD)' }}>{stats.unique_macs} MACs</div></div>
        <div className="sc"><div style={{ fontSize: 9, color: 'var(--txM)', textTransform: 'uppercase', letterSpacing: '.07em', marginBottom: 2 }}>Sessions</div><div style={{ fontSize: 17, fontWeight: 600, fontFamily: 'var(--fd)' }}>{fN(stats.total_sessions)}</div><div style={{ fontSize: 9, color: 'var(--txD)' }}>{fD(stats.duration)}</div></div>
      </div>

      {stats.cleartext_credential_sessions > 0 && (
        <div style={{
          background: 'rgba(248,81,73,.1)', border: '1px solid rgba(248,81,73,.3)',
          borderRadius: 6, padding: '8px 10px', marginBottom: 12, fontSize: 10,
        }}>
          <div style={{ color: '#f85149', fontWeight: 600, marginBottom: 2 }}>Cleartext Credentials Detected</div>
          <div style={{ color: 'var(--txM)' }}>
            {stats.cleartext_credential_sessions} session{stats.cleartext_credential_sessions > 1 ? 's' : ''} with
            credentials in cleartext (HTTP Auth, FTP, SMTP)
          </div>
        </div>
      )}

      <PluginSections slotType="stats_section" pluginResults={pluginResults} uiSlots={uiSlots} dedicated={dedicated} onSelectNode={onSelectNode} />

      <Collapse title="Protocol Hierarchy" open={true}>
        {tree.map(t => (<div key={t.name} style={{ marginBottom: 4 }}><div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, padding: '3px 0' }}><span style={{ fontWeight: 600 }}>{t.name}</span><span style={{ color: 'var(--txM)' }}>{fN(t.pkts)} pkts · {fB(t.bytes)}</span></div>{t.children.map(ch => (<div key={ch.name} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, padding: '2px 0 2px 16px', color: 'var(--txM)' }}><span>└ {ch.name}</span><span>{fN(ch.pkts)} · {fB(ch.bytes)}</span></div>))}</div>))}
      </Collapse>

      <Collapse title="Top Talkers" open={true}>
        {(stats.top_talkers || []).map((t, i) => (<div key={t.ip} className="hr" onClick={() => onSelectNode && onSelectNode(t.ip)} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 4px', borderBottom: '1px solid var(--bd)', fontSize: 11, borderRadius: 3, cursor: 'pointer' }}><span><span style={{ color: 'var(--txD)', marginRight: 6, fontSize: 9 }}>{i + 1}</span>{t.ip}</span><span style={{ color: 'var(--txM)' }}>{fB(t.bytes)}</span></div>))}
      </Collapse>

      <Collapse title="Top Ports">
        {(stats.top_ports || []).map((p, i) => (<div key={p.port} className="hr" style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 4px', borderBottom: '1px solid var(--bd)', fontSize: 11, borderRadius: 3 }}><span><span style={{ color: 'var(--txD)', marginRight: 6, fontSize: 9 }}>{i + 1}</span>{p.port}{p.service && <span style={{ color: 'var(--txD)', marginLeft: 6 }}>({p.service})</span>}</span><span style={{ color: 'var(--txM)' }}>{fN(p.count)}</span></div>))}
      </Collapse>
    </div>
  );
}
