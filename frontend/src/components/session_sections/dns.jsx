export const order = 100;
export const prefix = 'dns_';
export const defaultOpen = true;

export function hasData(s) { return s.dns_queries?.length > 0; }

export function title(s) { return 'DNS (' + s.dns_queries.length + ')'; }

export default function DnsSection({ s }) {
  return <>
    {s.dns_queries.slice(0, 30).map((q, i) => {
      const isErr = q.rcode > 0;
      const rcodeColor = isErr ? '#f85149' : '#3fb950';
      return (
        <div key={i} style={{ fontSize: 10, padding: '5px 0', borderBottom: '1px solid var(--bd)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5, flexWrap: 'wrap' }}>
            <span style={{
              fontSize: 9, padding: '0 5px', borderRadius: 6, lineHeight: '15px',
              background: q.qr === 'response' ? 'rgba(63,185,80,.1)' : 'rgba(210,153,34,.1)',
              color: q.qr === 'response' ? '#3fb950' : '#d29922',
              border: '1px solid ' + (q.qr === 'response' ? 'rgba(63,185,80,.2)' : 'rgba(210,153,34,.2)'),
            }}>{q.qr}</span>
            {q.type_name && (
              <span style={{ fontSize: 9, padding: '0 4px', borderRadius: 4, background: 'rgba(136,136,136,.12)', color: 'var(--txD)', fontFamily: 'var(--fn)' }}>{q.type_name}</span>
            )}
            {q.qclass_name && q.qclass_name !== 'IN' && (
              <span style={{ fontSize: 9, padding: '0 4px', borderRadius: 4, background: 'rgba(210,153,34,.12)', color: '#d29922', fontFamily: 'var(--fn)' }}>{q.qclass_name}</span>
            )}
            <span style={{ color: 'var(--txM)', fontFamily: 'var(--fn)', wordBreak: 'break-all' }}>{q.query}</span>
            {q.qr === 'response' && q.rcode_name && (
              <span style={{ fontSize: 9, padding: '0 5px', borderRadius: 6, lineHeight: '15px', marginLeft: 'auto', flexShrink: 0,
                background: isErr ? 'rgba(248,81,73,.1)' : 'rgba(63,185,80,.06)',
                color: rcodeColor, border: '1px solid ' + (isErr ? 'rgba(248,81,73,.2)' : 'rgba(63,185,80,.15)'),
              }}>{q.rcode_name}</span>
            )}
          </div>
          {q.answer_records?.length > 0 && (
            <div style={{ marginTop: 3, paddingLeft: 10 }}>
              {q.answer_records.slice(0, 10).map((r, ri) => (
                <div key={ri} style={{ fontSize: 9, color: 'var(--txD)', padding: '1px 0', display: 'flex', gap: 6, alignItems: 'baseline' }}>
                  <span style={{ color: 'var(--txD)', minWidth: 36, flexShrink: 0, fontFamily: 'var(--fn)' }}>{r.type_name || ''}</span>
                  <span style={{ color: 'var(--txM)', fontFamily: 'var(--fn)', wordBreak: 'break-all', flex: 1 }}>{r.data || ''}</span>
                  {r.ttl != null && <span style={{ color: 'var(--txD)', fontSize: 9, flexShrink: 0, fontFamily: 'var(--fn)' }}>TTL {r.ttl}</span>}
                </div>
              ))}
            </div>
          )}
          {!q.answer_records?.length && q.answers?.length > 0 && (
            <div style={{ fontSize: 9, color: 'var(--txD)', marginTop: 2, paddingLeft: 10, fontFamily: 'var(--fn)' }}>
              → {q.answers.join(', ')}
            </div>
          )}
          {q.authority_records?.length > 0 && (
            <div style={{ marginTop: 2, paddingLeft: 10 }}>
              <span style={{ fontSize: 9, color: 'var(--txD)' }}>AUTHORITY</span>
              {q.authority_records.slice(0, 5).map((r, ri) => (
                <div key={ri} style={{ fontSize: 9, color: 'var(--txD)', display: 'flex', gap: 6 }}>
                  <span style={{ minWidth: 36, fontFamily: 'var(--fn)' }}>{r.type_name || ''}</span>
                  <span style={{ color: 'var(--txM)', fontFamily: 'var(--fn)', wordBreak: 'break-all' }}>{r.data || r.name || ''}</span>
                </div>
              ))}
            </div>
          )}
          {q.flags && Object.keys(q.flags).length > 0 && (
            <div style={{ display: 'flex', gap: 4, marginTop: 3, paddingLeft: 10 }}>
              {Object.keys(q.flags).map(f => (
                <span key={f} style={{ fontSize: 9, padding: '0 4px', borderRadius: 3, background: 'rgba(136,136,136,.1)', color: 'var(--txD)', fontFamily: 'var(--fn)', textTransform: 'uppercase' }}>{f}</span>
              ))}
              {q.tx_id != null && <span style={{ fontSize: 9, color: 'var(--txD)', fontFamily: 'var(--fn)', marginLeft: 'auto' }}>ID 0x{q.tx_id.toString(16).padStart(4, '0')}</span>}
            </div>
          )}
        </div>
      );
    })}
  </>;
}
