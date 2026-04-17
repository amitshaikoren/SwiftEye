import Tag from '../../../components/Tag';
import Row from '../../../components/Row';

export const order = 5;
export const layer = 'Link (L2)';
export const prefix = 'arp_';
export const defaultOpen = true;

export function hasData(s) {
  return s.arp_opcodes?.length > 0;
}

export function title() {
  return 'ARP';
}

export default function ArpSection({ s }) {
  return <>
    {s.arp_opcodes?.length > 0 && (
      <div style={{ marginBottom: 6 }}>
        <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 3 }}>Opcodes</div>
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {s.arp_opcodes.map((op, i) => (
            <Tag key={i} small>{op.opcode} ({op.count})</Tag>
          ))}
        </div>
      </div>
    )}
    {s.arp_src_macs?.length > 0 && (
      <Row l="Sender MACs" v={s.arp_src_macs.join(', ')} />
    )}
    {s.arp_dst_macs?.length > 0 && (
      <Row l="Target MACs" v={s.arp_dst_macs.join(', ')} />
    )}
    {s.arp_src_ips?.length > 0 && (
      <Row l="Sender IPs" v={s.arp_src_ips.join(', ')} />
    )}
    {s.arp_dst_ips?.length > 0 && (
      <Row l="Target IPs" v={s.arp_dst_ips.join(', ')} />
    )}
    {s.arp_broadcast_count > 0 && (
      <Row l="Broadcasts" v={s.arp_broadcast_count} />
    )}
  </>;
}
