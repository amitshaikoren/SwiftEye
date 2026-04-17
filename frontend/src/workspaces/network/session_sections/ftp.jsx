import Row from '../../../components/Row';

export const order = 40;
export const prefix = 'ftp_';
export const defaultOpen = false;

export function hasData(s) {
  return s.ftp_usernames?.length > 0 || s.ftp_transfer_files?.length > 0 ||
    s.ftp_has_credentials || s.ftp_fwd_commands?.length > 0 || s.ftp_rev_response_codes?.length > 0;
}

export function title(s) {
  return 'FTP' + (s.ftp_has_credentials ? ' \u26A0 Credentials' : '');
}

export default function FtpSection({ s }) {
  return <>
    {s.ftp_has_credentials && (
      <div style={{ fontSize: 10, color: 'var(--acO)', marginBottom: 4 }}>{'\u26A0'} USER/PASS sequence detected — credentials in cleartext</div>
    )}
    {s.ftp_usernames?.length > 0 && <Row l="Username(s)" v={s.ftp_usernames.join(', ')} />}
    {s.ftp_transfer_files?.length > 0 && (
      <div style={{ marginTop: 4 }}>
        <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 2 }}>Files transferred</div>
        {s.ftp_transfer_files.slice(0, 10).map((f, i) => (
          <div key={i} style={{ fontSize: 10, color: 'var(--txD)', padding: '1px 0', fontFamily: 'var(--fn)' }}>{f}</div>
        ))}
      </div>
    )}
    {(s.ftp_fwd_commands?.length > 0 || s.ftp_fwd_transfer_mode) && (
      <div style={{ marginTop: 6, paddingTop: 4, borderTop: '1px solid var(--bd)' }}>
        <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 4 }}>Initiator →</div>
        {s.ftp_fwd_commands?.length > 0 && <Row l="Commands" v={[...new Set(s.ftp_fwd_commands)].join(', ')} />}
        {s.ftp_fwd_transfer_mode && <Row l="Transfer mode" v={s.ftp_fwd_transfer_mode} />}
      </div>
    )}
    {(s.ftp_rev_response_codes?.length > 0 || s.ftp_rev_server_banner) && (
      <div style={{ marginTop: 6, paddingTop: 4, borderTop: '1px solid var(--bd)' }}>
        <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 4 }}>Responder ←</div>
        {s.ftp_rev_server_banner && <Row l="Banner" v={s.ftp_rev_server_banner} />}
        {s.ftp_rev_response_codes?.length > 0 && <Row l="Response codes" v={[...new Set(s.ftp_rev_response_codes)].sort((a,b) => a-b).join(', ')} />}
      </div>
    )}
  </>;
}
