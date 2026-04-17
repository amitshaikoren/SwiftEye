import Collapse from '../../../core/components/Collapse';
import Row from '../../../core/components/Row';

export const order = 20;
export const prefix = 'http_';
export const defaultOpen = true;

export function hasData(s) {
  return s.http_hosts?.length > 0 || s.http_fwd_user_agents?.length > 0 ||
    s.http_fwd_methods?.length > 0 || s.http_rev_servers?.length > 0 || s.http_rev_status_codes?.length > 0;
}

export function title() { return 'HTTP'; }

export default function HttpSection({ s }) {
  return <>
    {s.http_hosts?.length > 0 && <Row l="Host(s)" v={s.http_hosts.join(', ')} />}
    {/* Initiator → */}
    {(s.http_fwd_user_agents?.length > 0 || s.http_fwd_methods?.length > 0 || s.http_fwd_uris?.length > 0 || s.http_fwd_referers?.length > 0 || s.http_fwd_has_cookies || s.http_fwd_has_auth) && (
      <div style={{ marginTop: 6, paddingTop: 4, borderTop: '1px solid var(--bd)' }}>
        <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 4 }}>Initiator →</div>
        {s.http_fwd_methods?.length > 0 && <Row l="Methods" v={s.http_fwd_methods.join(', ')} />}
        {s.http_fwd_user_agents?.length > 0 && (
          <div style={{ marginBottom: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 2 }}>User-Agent(s)</div>
            {s.http_fwd_user_agents.map(ua => (
              <div key={ua} style={{ fontSize: 9, fontFamily: 'var(--fn)', color: 'var(--txM)', padding: '1px 0', wordBreak: 'break-all' }}>{ua}</div>
            ))}
          </div>
        )}
        {s.http_fwd_uris?.length > 0 && (
          <Collapse title={`URIs (${s.http_fwd_uris.length})`}>
            {s.http_fwd_uris.slice(0, 20).map((u, i) => (
              <div key={i} style={{ fontSize: 9, fontFamily: 'var(--fn)', color: 'var(--txM)', padding: '1px 0', wordBreak: 'break-all' }}>{u}</div>
            ))}
          </Collapse>
        )}
        {s.http_fwd_referers?.length > 0 && <Row l="Referer(s)" v={s.http_fwd_referers.join(', ')} />}
        {s.http_fwd_has_cookies && <Row l="Cookies" v="present" />}
        {s.http_fwd_has_auth && (
          <>
            <Row l="Authorization" v={
              s.http_fwd_auth_types?.length > 0
                ? s.http_fwd_auth_types.join(', ') + ' \u2014 cleartext credentials'
                : 'present'
            } />
            {s.http_fwd_usernames?.length > 0 && (
              <Row l="Username(s)" v={s.http_fwd_usernames.join(', ')} />
            )}
          </>
        )}
      </div>
    )}
    {/* Responder ← */}
    {(s.http_rev_servers?.length > 0 || s.http_rev_status_codes?.length > 0 || s.http_rev_content_types?.length > 0 || s.http_rev_redirects?.length > 0 || s.http_rev_has_set_cookies) && (
      <div style={{ marginTop: 6, paddingTop: 4, borderTop: '1px solid var(--bd)' }}>
        <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 4 }}>Responder ←</div>
        {s.http_rev_servers?.length > 0 && <Row l="Server(s)" v={s.http_rev_servers.join(', ')} />}
        {s.http_rev_status_codes?.length > 0 && (
          <Row l="Status codes" v={[...new Set(s.http_rev_status_codes)].sort((a,b) => a-b).join(', ')} />
        )}
        {s.http_rev_content_types?.length > 0 && <Row l="Content-Type(s)" v={s.http_rev_content_types.join(', ')} />}
        {s.http_rev_redirects?.length > 0 && (
          <div style={{ marginBottom: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 2 }}>Redirects</div>
            {s.http_rev_redirects.map(r => (
              <div key={r} style={{ fontSize: 9, fontFamily: 'var(--fn)', color: 'var(--txD)', padding: '1px 0', wordBreak: 'break-all' }}>{r}</div>
            ))}
          </div>
        )}
        {s.http_rev_has_set_cookies && <Row l="Set-Cookie" v="present" />}
      </div>
    )}
  </>;
}
