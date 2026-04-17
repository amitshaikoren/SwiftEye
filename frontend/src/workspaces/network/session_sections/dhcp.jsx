import Row from '../../../components/Row';

export const order = 50;
export const prefix = 'dhcp_';
export const defaultOpen = false;

export function hasData(s) {
  return s.dhcp_hostnames?.length > 0 || s.dhcp_vendor_classes?.length > 0 ||
    s.dhcp_msg_types?.length > 0 || s.dhcp_lease_time || s.dhcp_server_ids?.length > 0;
}

export function title() { return 'DHCP'; }

export default function DhcpSection({ s }) {
  return <>
    {s.dhcp_msg_types?.length > 0 && <Row l="Message types" v={s.dhcp_msg_types.join(' → ')} />}
    {s.dhcp_hostnames?.length > 0 && <Row l="Hostname(s)" v={s.dhcp_hostnames.join(', ')} />}
    {s.dhcp_vendor_classes?.length > 0 && (
      <div style={{ marginBottom: 4 }}>
        <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 2 }}>Vendor class</div>
        {s.dhcp_vendor_classes.map(v => (
          <div key={v} style={{ fontSize: 10, color: 'var(--txD)', fontFamily: 'var(--fn)' }}>{v}</div>
        ))}
      </div>
    )}
    {s.dhcp_server_ids?.length > 0 && <Row l="Server ID" v={s.dhcp_server_ids.join(', ')} />}
    {s.dhcp_lease_time != null && <Row l="Lease time" v={`${s.dhcp_lease_time}s (${Math.round(s.dhcp_lease_time / 60)}m)`} />}
    {s.dhcp_routers?.length > 0 && <Row l="Router" v={s.dhcp_routers.join(', ')} />}
    {s.dhcp_dns_servers?.length > 0 && <Row l="DNS servers" v={s.dhcp_dns_servers.join(', ')} />}
    {s.dhcp_options_seen?.length > 0 && <Row l="Options seen" v={s.dhcp_options_seen.join(', ')} />}
  </>;
}
