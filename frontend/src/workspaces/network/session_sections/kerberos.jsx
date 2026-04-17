import Collapse from '../../../components/Collapse';
import Row from '../../../components/Row';

export const order = 80;
export const prefix = 'krb_';
export const defaultOpen = false;

export function hasData(s) { return s.krb_msg_types?.length > 0; }
export function title() { return 'Kerberos'; }

export default function KerberosSection({ s }) {
  return <>
    <Row l="Message types" v={s.krb_msg_types.join(', ')} />
    {s.krb_realms?.length > 0 && <Row l="Realm(s)" v={s.krb_realms.join(', ')} />}
    {s.krb_cnames?.length > 0 && (
      <div style={{ marginTop: 4 }}>
        <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 2 }}>Client principal(s)</div>
        {s.krb_cnames.map(c => <div key={c} style={{ fontSize: 10, fontFamily: 'var(--fn)', color: 'var(--acG)', padding: '1px 0' }}>{c}</div>)}
      </div>
    )}
    {s.krb_snames?.length > 0 && (
      <div style={{ marginTop: 4 }}>
        <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 2 }}>Service principal(s)</div>
        {s.krb_snames.map(c => <div key={c} style={{ fontSize: 10, fontFamily: 'var(--fn)', color: 'var(--ac)', padding: '1px 0' }}>{c}</div>)}
      </div>
    )}
    {s.krb_etypes?.length > 0 && (
      <Collapse title={`Encryption types (${s.krb_etypes.length})`}>
        {s.krb_etypes.map(e => <div key={e} style={{ fontSize: 9, fontFamily: 'var(--fn)', color: 'var(--txM)', padding: '1px 0' }}>{e}</div>)}
      </Collapse>
    )}
    {s.krb_error_codes?.length > 0 && (
      <div style={{ marginTop: 4, paddingTop: 4, borderTop: '1px solid var(--bd)' }}>
        <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 2 }}>Errors</div>
        {s.krb_error_codes.map((e, i) => (
          <div key={i} style={{ fontSize: 10, fontFamily: 'var(--fn)', color: '#f85149', padding: '1px 0' }}>{e.name} ({e.code})</div>
        ))}
      </div>
    )}
  </>;
}
