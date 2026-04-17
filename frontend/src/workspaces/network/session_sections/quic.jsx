import Collapse from '../../../components/Collapse';
import Row from '../../../components/Row';

export const order = 110;
export const prefix = 'quic_';
export const defaultOpen = false;

export function hasData(s) { return s.quic_versions?.length > 0 || s.quic_snis?.length > 0; }

export function title(s) {
  return 'QUIC' + (s.quic_versions?.length ? ' (' + s.quic_versions.join(', ') + ')' : '');
}

export default function QuicSection({ s }) {
  return <>
    {s.quic_snis?.length > 0 && <Row l="SNI" v={s.quic_snis.join(', ')} vColor="var(--acC)" />}
    {s.quic_alpn?.length > 0 && <Row l="ALPN" v={s.quic_alpn.join(', ')} />}
    {s.quic_packet_types?.length > 0 && <Row l="Packet types" v={s.quic_packet_types.join(', ')} />}
    {s.quic_tls_versions?.length > 0 && <Row l="TLS versions" v={s.quic_tls_versions.join(', ')} />}
    {s.quic_tls_ciphers?.length > 0 && (
      <Collapse title={'Cipher suites (' + s.quic_tls_ciphers.length + ')'}>
        {s.quic_tls_ciphers.map(c => <div key={c} style={{ fontSize: 9, color: 'var(--txM)', fontFamily: 'var(--fn)', padding: '1px 0' }}>{c}</div>)}
      </Collapse>
    )}
    {s.quic_dcids?.length > 0 && <Row l="DCID" v={s.quic_dcids.join(', ')} />}
    {s.quic_scids?.length > 0 && <Row l="SCID" v={s.quic_scids.join(', ')} />}
  </>;
}
