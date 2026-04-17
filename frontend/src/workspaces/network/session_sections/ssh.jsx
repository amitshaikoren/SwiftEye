import Collapse from '../../../components/Collapse';
import Row from '../../../components/Row';

export const order = 30;
export const prefix = 'ssh_';
export const defaultOpen = false;

export function hasData(s) {
  return s.ssh_fwd_banners?.length > 0 || s.ssh_rev_banners?.length > 0 || s.ssh_kex_algorithms?.length > 0;
}

export function title() { return 'SSH'; }

export default function SshSection({ s }) {
  return <>
    {s.ssh_fwd_banners?.length > 0 && (
      <div style={{ marginBottom: 4 }}>
        <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 2 }}>Initiator → banner</div>
        {s.ssh_fwd_banners.map(b => <div key={b} style={{ fontSize: 10, fontFamily: 'var(--fn)', color: 'var(--acG)', padding: '1px 0' }}>{b}</div>)}
      </div>
    )}
    {s.ssh_rev_banners?.length > 0 && (
      <div style={{ marginBottom: 4 }}>
        <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 2 }}>Responder ← banner</div>
        {s.ssh_rev_banners.map(b => <div key={b} style={{ fontSize: 10, fontFamily: 'var(--fn)', color: 'var(--ac)', padding: '1px 0' }}>{b}</div>)}
      </div>
    )}
    {s.ssh_kex_algorithms?.length > 0 && (
      <Collapse title={`KEX algorithms (${s.ssh_kex_algorithms.length})`}>
        {s.ssh_kex_algorithms.map(a => <div key={a} style={{ fontSize: 9, fontFamily: 'var(--fn)', color: 'var(--txM)', padding: '1px 0' }}>{a}</div>)}
      </Collapse>
    )}
    {s.ssh_host_key_algorithms?.length > 0 && (
      <Collapse title={`Host key types (${s.ssh_host_key_algorithms.length})`}>
        {s.ssh_host_key_algorithms.map(a => <div key={a} style={{ fontSize: 9, fontFamily: 'var(--fn)', color: 'var(--txM)', padding: '1px 0' }}>{a}</div>)}
      </Collapse>
    )}
    {s.ssh_encryption_c2s?.length > 0 && (
      <Collapse title={`Encryption → (${s.ssh_encryption_c2s.length})`}>
        {s.ssh_encryption_c2s.map(a => <div key={a} style={{ fontSize: 9, fontFamily: 'var(--fn)', color: 'var(--txM)', padding: '1px 0' }}>{a}</div>)}
      </Collapse>
    )}
    {s.ssh_encryption_s2c?.length > 0 && (
      <Collapse title={`Encryption ← (${s.ssh_encryption_s2c.length})`}>
        {s.ssh_encryption_s2c.map(a => <div key={a} style={{ fontSize: 9, fontFamily: 'var(--fn)', color: 'var(--txM)', padding: '1px 0' }}>{a}</div>)}
      </Collapse>
    )}
    {s.ssh_mac_c2s?.length > 0 && <Row l="MAC →" v={s.ssh_mac_c2s.join(', ')} />}
    {s.ssh_mac_s2c?.length > 0 && <Row l="MAC ←" v={s.ssh_mac_s2c.join(', ')} />}
  </>;
}
