import Collapse from '../../../components/Collapse';
import Row from '../../../components/Row';
import Tag from '../../../components/Tag';

export const order = 10;
export const prefix = ['tls_', 'ja3_', 'ja4_'];
export const defaultOpen = false;

export function hasData(s) {
  return s.tls_snis?.length > 0 || s.tls_versions?.length > 0 || s.tls_selected_ciphers?.length > 0 ||
    s.ja3_hashes?.length > 0 || s.ja4_hashes?.length > 0 || s.tls_cert ||
    s.tls_fwd_alpn_offered?.length > 0 || s.tls_rev_alpn_selected ||
    s.tls_fwd_supported_versions?.length > 0 || s.tls_cert_chain?.length > 0;
}

export function title(s) {
  return 'TLS' + (s.tls_versions?.length ? ' ' + s.tls_versions[0] : '');
}

function JA3Badge({ hash, apps = [] }) {
  const app = apps.find(a => a.hash === hash);
  return (
    <div style={{ padding: '2px 0', display: 'flex', alignItems: 'baseline', gap: 6, flexWrap: 'wrap' }}>
      <span style={{ fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--ac)', wordBreak: 'break-all' }}>{hash}</span>
      {app && (
        <span style={{
          fontSize: 9, padding: '0 5px', borderRadius: 6, flexShrink: 0,
          background: app.is_malware ? 'rgba(248,81,73,.15)' : 'rgba(63,185,80,.08)',
          color: app.is_malware ? 'var(--acR)' : 'var(--acG)',
          border: '1px solid ' + (app.is_malware ? 'rgba(248,81,73,.3)' : 'rgba(63,185,80,.2)'),
          fontFamily: 'var(--fn)',
        }}>
          {app.is_malware ? '\u26A0 ' : ''}{app.name}
        </span>
      )}
    </div>
  );
}

export default function TlsSection({ s }) {
  return <>
    {s.tls_snis?.length > 0 && (
      <div style={{ marginBottom: 6 }}>
        <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 3 }}>SNI</div>
        {s.tls_snis.map(sni => <div key={sni} style={{ fontSize: 11, padding: '2px 0' }}>{sni}</div>)}
      </div>
    )}
    {s.tls_versions?.length > 0 && (
      <div style={{ marginBottom: 6 }}>
        <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 3 }}>Version</div>
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {s.tls_versions.map(v => <Tag key={v} color="#2dd4bf" small>{v}</Tag>)}
        </div>
      </div>
    )}
    {s.tls_selected_ciphers?.length > 0 && (
      <div style={{ marginBottom: 6 }}>
        <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 3 }}>Selected cipher</div>
        {s.tls_selected_ciphers.map(c => <div key={c} style={{ fontSize: 10, color: 'var(--acG)', padding: '2px 0' }}>{c}</div>)}
      </div>
    )}
    {/* Initiator → ClientHello details */}
    {(s.tls_fwd_alpn_offered?.length > 0 || s.tls_fwd_supported_versions?.length > 0) && (
      <div style={{ marginBottom: 6, paddingTop: 4, borderTop: '1px solid var(--bd)' }}>
        <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 4 }}>Initiator → (ClientHello)</div>
        {s.tls_fwd_supported_versions?.length > 0 && (
          <Row l="Supported versions" v={s.tls_fwd_supported_versions.join(', ')} />
        )}
        {s.tls_fwd_alpn_offered?.length > 0 && (
          <Row l="ALPN offered" v={s.tls_fwd_alpn_offered.join(', ')} />
        )}
        {s.tls_fwd_compression_methods?.length > 0 && s.tls_fwd_compression_methods.some(m => m !== 0) && (
          <Row l="Compression" v={s.tls_fwd_compression_methods.join(', ')} />
        )}
      </div>
    )}
    {/* Responder ← ServerHello details */}
    {(s.tls_rev_alpn_selected || s.tls_rev_selected_version || s.tls_rev_key_exchange_group || s.tls_rev_session_resumption) && (
      <div style={{ marginBottom: 6, paddingTop: 4, borderTop: '1px solid var(--bd)' }}>
        <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 4 }}>Responder ← (ServerHello)</div>
        {s.tls_rev_selected_version && <Row l="Selected version" v={s.tls_rev_selected_version} />}
        {s.tls_rev_alpn_selected && <Row l="ALPN selected" v={s.tls_rev_alpn_selected} />}
        {s.tls_rev_key_exchange_group != null && <Row l="Key exchange group" v={String(s.tls_rev_key_exchange_group)} />}
        {s.tls_rev_session_resumption && <Row l="Session resumption" v={s.tls_rev_session_resumption} />}
      </div>
    )}
    {s.tls_cert && (
      <Collapse title="Certificate (leaf)">
        {s.tls_cert.subject_cn && <Row l="Subject" v={s.tls_cert.subject_cn} />}
        {s.tls_cert.issuer    && <Row l="Issuer"  v={s.tls_cert.issuer} />}
        {s.tls_cert.not_before && s.tls_cert.not_after && (
          <Row l="Valid" v={`${s.tls_cert.not_before} → ${s.tls_cert.not_after}`} />
        )}
        {s.tls_cert.sans?.length > 0 && (
          <div style={{ marginTop: 4 }}>
            <div style={{ fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 3 }}>SANs ({s.tls_cert.sans.length})</div>
            {s.tls_cert.sans.slice(0, 10).map(san => (
              <div key={san} style={{ fontSize: 9, fontFamily: 'var(--fn)', color: 'var(--txM)', padding: '1px 0' }}>{san}</div>
            ))}
            {s.tls_cert.sans.length > 10 && (
              <div style={{ fontSize: 9, color: 'var(--txD)' }}>+{s.tls_cert.sans.length - 10} more</div>
            )}
          </div>
        )}
        {s.tls_cert.serial && <Row l="Serial" v={s.tls_cert.serial} />}
      </Collapse>
    )}
    {s.tls_cert_chain?.length > 0 && (
      <Collapse title={`Certificate chain (${s.tls_cert_chain.length} intermediate${s.tls_cert_chain.length > 1 ? 's' : ''})`}>
        {s.tls_cert_chain.map((c, i) => (
          <div key={i} style={{ fontSize: 10, padding: '3px 0', borderBottom: '1px solid var(--bd)' }}>
            {c.subject_cn && <Row l="Subject" v={c.subject_cn} />}
            {c.issuer && <Row l="Issuer" v={c.issuer} />}
          </div>
        ))}
      </Collapse>
    )}
    {(s.ja3_hashes?.length > 0 || s.ja4_hashes?.length > 0) && (
      <div style={{ marginTop: 4, paddingTop: 4, borderTop: '1px solid var(--bd)' }}>
        {s.ja3_hashes?.map(h => (
          <div key={h} style={{ marginBottom: 2 }}>
            <span style={{ fontSize: 9, color: 'var(--txD)', marginRight: 5 }}>JA3</span>
            <JA3Badge hash={h} apps={s.ja3_apps || []} />
          </div>
        ))}
        {s.ja4_hashes?.map(h => (
          <div key={h} style={{ marginBottom: 2, display: 'flex', alignItems: 'baseline', gap: 6, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 9, color: 'var(--txD)', flexShrink: 0 }}>JA4</span>
            <span style={{ fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--acP)', wordBreak: 'break-all' }}>{h}</span>
          </div>
        ))}
      </div>
    )}
    {s.tls_ciphers?.length > 0 && (
      <Collapse title={'Offered ciphers (' + s.tls_ciphers.length + ')'}>
        {s.tls_ciphers.map(c => <div key={c} style={{ fontSize: 10, color: 'var(--txM)', padding: '1px 0' }}>{c}</div>)}
      </Collapse>
    )}
  </>;
}
