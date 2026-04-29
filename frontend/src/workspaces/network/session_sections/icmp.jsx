import Collapse from '../../../core/components/Collapse';
import Row from '../../../core/components/Row';

export const order = 70;
export const layer = 'Network (L3)';
export const prefix = 'icmp_';
export const defaultOpen = false;

export function hasData(s) {
  return s.icmp_fwd_types?.length > 0 || s.icmp_rev_types?.length > 0;
}

export function title() { return 'ICMP'; }

function IcmpDirection({ label, types, identifiers, payloadSizes, payloadSamples }) {
  if (!types?.length) return null;
  return (
    <div style={{ marginBottom: 6 }}>
      <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 3 }}>{label}</div>
      {types.map((t, i) => (
        <div key={i} style={{ fontSize: 10, padding: '2px 0', display: 'flex', justifyContent: 'space-between' }}>
          <span style={{ fontFamily: 'var(--fn)', color: 'var(--txM)' }}>{t.type_desc}</span>
          <span style={{ fontSize: 9, color: 'var(--txD)' }}>×{t.count}</span>
        </div>
      ))}
      {identifiers?.length > 0 && <Row l="Identifiers" v={identifiers.map(id => `0x${id.toString(16).padStart(4,'0')}`).join(', ')} />}
      {payloadSizes?.length > 0 && <Row l="Payload sizes" v={[...new Set(payloadSizes)].sort((a,b) => a-b).join(', ') + ' bytes'} />}
      {payloadSamples?.length > 0 && (
        <Collapse title={`Payload samples (${payloadSamples.length})`}>
          {payloadSamples.map((hex, i) => (
            <div key={i} style={{ fontSize: 9, fontFamily: 'var(--fn)', color: 'var(--txD)', padding: '2px 0', wordBreak: 'break-all' }}>{hex}</div>
          ))}
        </Collapse>
      )}
    </div>
  );
}

export default function IcmpSection({ s }) {
  return <>
    <IcmpDirection label="Initiator →" types={s.icmp_fwd_types} identifiers={s.icmp_fwd_identifiers}
      payloadSizes={s.icmp_fwd_payload_sizes} payloadSamples={s.icmp_fwd_payload_samples} />
    {s.icmp_rev_types?.length > 0 && (
      <div style={{ paddingTop: 4, borderTop: '1px solid var(--bd)' }}>
        <IcmpDirection label="Responder ←" types={s.icmp_rev_types} identifiers={s.icmp_rev_identifiers}
          payloadSizes={s.icmp_rev_payload_sizes} payloadSamples={s.icmp_rev_payload_samples} />
      </div>
    )}
  </>;
}
