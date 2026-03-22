import Tag from '../Tag';
import Row from '../Row';

export const order = 60;
export const prefix = 'smb_';
export const defaultOpen = false;

export function hasData(s) {
  return s.smb_versions?.length > 0 || s.smb_tree_paths?.length > 0 ||
    s.smb_filenames?.length > 0 || s.smb_fwd_operations?.length > 0 || s.smb_rev_status_codes?.length > 0;
}

export function title(s) {
  return 'SMB' + (s.smb_versions?.length ? ' (' + s.smb_versions.join(', ') + ')' : '');
}

export default function SmbSection({ s }) {
  return <>
    {s.smb_tree_paths?.length > 0 && (
      <div style={{ marginBottom: 6 }}>
        <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 2 }}>Share paths</div>
        {s.smb_tree_paths.map(p => (
          <div key={p} style={{ fontSize: 10, color: 'var(--ac)', fontFamily: 'var(--fn)', padding: '1px 0' }}>{p}</div>
        ))}
      </div>
    )}
    {s.smb_filenames?.length > 0 && (
      <div style={{ marginBottom: 6 }}>
        <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 2 }}>Filenames</div>
        {s.smb_filenames.slice(0, 15).map(f => (
          <div key={f} style={{ fontSize: 10, color: 'var(--txD)', fontFamily: 'var(--fn)', padding: '1px 0' }}>{f}</div>
        ))}
      </div>
    )}
    {s.smb_fwd_operations?.length > 0 && (
      <div style={{ marginTop: 4, paddingTop: 4, borderTop: '1px solid var(--bd)' }}>
        <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 2 }}>Initiator → operations</div>
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {s.smb_fwd_operations.map(op => <Tag key={op} small>{op}</Tag>)}
        </div>
      </div>
    )}
    {s.smb_rev_status_codes?.length > 0 && (
      <div style={{ marginTop: 4, paddingTop: 4, borderTop: '1px solid var(--bd)' }}>
        <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 2 }}>Responder ← status</div>
        {[...new Map(s.smb_rev_status_codes.map(c => [c.name, c])).values()].map((c, i) => (
          <div key={i} style={{ fontSize: 9, fontFamily: 'var(--fn)', color: c.code === 0 ? 'var(--acG)' : 'var(--acO)', padding: '1px 0' }}>{c.name}</div>
        ))}
      </div>
    )}
  </>;
}
