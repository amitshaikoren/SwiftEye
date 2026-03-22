import Collapse from '../Collapse';
import Row from '../Row';

export const order = 90;
export const prefix = 'ldap_';
export const defaultOpen = false;

export function hasData(s) { return s.ldap_ops?.length > 0; }
export function title() { return 'LDAP'; }

export default function LdapSection({ s }) {
  return <>
    <Row l="Operations" v={s.ldap_ops.join(', ')} />
    {s.ldap_bind_dns?.length > 0 && (
      <div style={{ marginTop: 4 }}>
        <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 2 }}>Bind DN(s)</div>
        {s.ldap_bind_dns.map(dn => <div key={dn} style={{ fontSize: 10, fontFamily: 'var(--fn)', color: 'var(--acG)', padding: '1px 0', wordBreak: 'break-all' }}>{dn || '(anonymous)'}</div>)}
      </div>
    )}
    {s.ldap_bind_mechanisms?.length > 0 && <Row l="Auth mechanism(s)" v={s.ldap_bind_mechanisms.join(', ')} />}
    {s.ldap_search_bases?.length > 0 && (
      <div style={{ marginTop: 4 }}>
        <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 2 }}>Search base(s)</div>
        {s.ldap_search_bases.map(b => <div key={b} style={{ fontSize: 10, fontFamily: 'var(--fn)', color: 'var(--txD)', padding: '1px 0', wordBreak: 'break-all' }}>{b || '(root)'}</div>)}
      </div>
    )}
    {s.ldap_entry_dns?.length > 0 && (
      <Collapse title={`Result entries (${s.ldap_entry_dns.length})`}>
        {s.ldap_entry_dns.map(dn => <div key={dn} style={{ fontSize: 9, fontFamily: 'var(--fn)', color: 'var(--txM)', padding: '1px 0', wordBreak: 'break-all' }}>{dn}</div>)}
      </Collapse>
    )}
    {s.ldap_result_codes?.length > 0 && (
      <div style={{ marginTop: 4, paddingTop: 4, borderTop: '1px solid var(--bd)' }}>
        <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 2 }}>Result codes</div>
        {[...new Map(s.ldap_result_codes.map(c => [c.name, c])).values()].map((c, i) => (
          <div key={i} style={{ fontSize: 10, fontFamily: 'var(--fn)', color: c.code === 0 ? 'var(--acG)' : 'var(--acO)', padding: '1px 0' }}>{c.name}</div>
        ))}
      </div>
    )}
  </>;
}
