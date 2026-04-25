/**
 * Forensic workspace — edge detail panel.
 *
 * Shows the event list for a clicked edge: each row displays ts,
 * action_type badge, and key fields from the event payload.
 * Events come from the edge's `events` array (already in the graph response)
 * so no secondary fetch is needed for Phase 5.
 */

import React, { useState } from 'react';

// ── Action-type badge colors ─────────────────────────────────────────────────

const ACTION_COLOR = {
  process_create:  { bg: 'rgba(79,195,247,.15)',  fg: '#4fc3f7',  label: 'Process Create' },
  network_connect: { bg: 'rgba(206,147,216,.15)', fg: '#ce93d8',  label: 'Network Connect' },
  file_create:     { bg: 'rgba(255,241,118,.15)', fg: '#c9a227',  label: 'File Create' },
  registry_set:    { bg: 'rgba(255,183,77,.15)',  fg: '#ffb74d',  label: 'Registry Set' },
};

function ActionBadge({ action }) {
  const m = ACTION_COLOR[action] || { bg: 'rgba(139,148,158,.15)', fg: '#8b949e', label: action };
  return (
    <span style={{
      fontSize: 9, padding: '1px 6px', borderRadius: 6,
      background: m.bg, color: m.fg,
      border: '1px solid ' + m.fg + '44',
      fontWeight: 600, whiteSpace: 'nowrap', letterSpacing: '0.04em',
    }}>
      {m.label}
    </span>
  );
}

// ── Key fields to surface per action type ────────────────────────────────────

function eventSummary(action, fields) {
  if (!fields) return null;
  const items = [];
  if (action === 'process_create') {
    if (fields.command_line) items.push({ k: 'cmdline', v: fields.command_line });
    if (fields.integrity_level) items.push({ k: 'integrity', v: fields.integrity_level });
    if (fields.hashes) items.push({ k: 'hashes', v: fields.hashes });
  } else if (action === 'network_connect') {
    if (fields.protocol) items.push({ k: 'proto', v: fields.protocol });
    if (fields.local_ip) items.push({ k: 'local', v: `${fields.local_ip}:${fields.local_port || '?'}` });
  } else if (action === 'file_create') {
    if (fields.creation_utc_time) items.push({ k: 'created', v: fields.creation_utc_time });
    if (fields.hashes) items.push({ k: 'hashes', v: fields.hashes });
  } else if (action === 'registry_set') {
    if (fields.details) items.push({ k: 'value', v: fields.details });
    if (fields.event_type) items.push({ k: 'type', v: fields.event_type });
  }
  return items;
}

function formatTs(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
  } catch {
    return iso;
  }
}

// ── Event row ────────────────────────────────────────────────────────────────

function EventRow({ ev, expanded, onToggle }) {
  const summary = eventSummary(ev.action_type, ev.fields);
  return (
    <div
      style={{
        borderBottom: '1px solid var(--bd)', padding: '7px 0',
        cursor: summary?.length ? 'pointer' : 'default',
      }}
      onClick={() => summary?.length && onToggle()}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
        <ActionBadge action={ev.action_type} />
        <span style={{ fontSize: 10, color: 'var(--txD)', fontFamily: 'var(--fn)', flex: 1 }}>
          {formatTs(ev.ts)}
        </span>
        {summary?.length > 0 && (
          <span style={{ fontSize: 9, color: 'var(--txD)' }}>{expanded ? '▲' : '▼'}</span>
        )}
      </div>
      {expanded && summary?.length > 0 && (
        <div style={{ marginTop: 6, paddingLeft: 4 }}>
          {summary.map(({ k, v }) => (
            <div key={k} style={{ display: 'flex', gap: 6, marginBottom: 2, alignItems: 'flex-start' }}>
              <span style={{ fontSize: 9, color: 'var(--txD)', minWidth: 56, flexShrink: 0 }}>{k}</span>
              <span style={{
                fontSize: 10, color: 'var(--txM)', fontFamily: 'var(--fn)',
                wordBreak: 'break-all', lineHeight: 1.4,
              }}>{v}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

const PAGE = 50;

export default function ForensicEdgeDetail({ edge, onClear }) {
  const [expandedIdx, setExpandedIdx] = useState(null);
  const [page, setPage] = useState(0);

  if (!edge) return null;

  const events = edge.events || [];
  const total = events.length;
  const start = page * PAGE;
  const pageEvents = events.slice(start, start + PAGE);
  const pages = Math.ceil(total / PAGE);

  const srcId = typeof edge.source === 'object' ? edge.source.id : edge.source;
  const dstId = typeof edge.target === 'object' ? edge.target.id : edge.target;

  return (
    <div style={{ fontFamily: 'var(--fn)', fontSize: 12, color: 'var(--tx)', padding: '10px 14px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 12 }}>
        <span style={{
          fontSize: 9, padding: '2px 7px', borderRadius: 8, fontWeight: 600,
          background: 'rgba(139,148,158,.12)', color: 'var(--txM)',
          border: '1px solid rgba(139,148,158,.2)',
          textTransform: 'uppercase', letterSpacing: '0.06em',
        }}>
          {edge.type || 'edge'}
        </span>
        <span style={{ flex: 1, fontSize: 10, color: 'var(--txD)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {total} event{total !== 1 ? 's' : ''}
        </span>
        {onClear && (
          <button
            onClick={onClear}
            style={{ background: 'none', border: 'none', color: 'var(--txD)', cursor: 'pointer', fontSize: 14, lineHeight: 1, padding: 2 }}
          >×</button>
        )}
      </div>

      {/* Entity pair */}
      <div style={{ marginBottom: 10, fontSize: 10, color: 'var(--txD)', overflow: 'hidden' }}>
        <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={srcId}>src: {srcId}</div>
        <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={dstId}>dst: {dstId}</div>
      </div>

      {/* Time range */}
      {(edge.ts_first || edge.ts_last) && (
        <div style={{ marginBottom: 10, fontSize: 10, color: 'var(--txD)' }}>
          {edge.ts_first && <div>First: {formatTs(edge.ts_first)}</div>}
          {edge.ts_last  && <div>Last:  {formatTs(edge.ts_last)}</div>}
        </div>
      )}

      {/* Events list */}
      {total === 0 ? (
        <div style={{ color: 'var(--txD)', fontSize: 11 }}>No events on this edge.</div>
      ) : (
        <>
          {pageEvents.map((ev, i) => (
            <EventRow
              key={start + i}
              ev={ev}
              expanded={expandedIdx === start + i}
              onToggle={() => setExpandedIdx(p => p === start + i ? null : start + i)}
            />
          ))}
          {pages > 1 && (
            <div style={{ display: 'flex', gap: 6, marginTop: 8, justifyContent: 'center' }}>
              <button
                className="btn" disabled={page === 0}
                onClick={() => { setPage(p => p - 1); setExpandedIdx(null); }}
                style={{ fontSize: 10, padding: '2px 8px' }}
              >‹</button>
              <span style={{ fontSize: 10, color: 'var(--txD)', lineHeight: '22px' }}>
                {page + 1} / {pages}
              </span>
              <button
                className="btn" disabled={page >= pages - 1}
                onClick={() => { setPage(p => p + 1); setExpandedIdx(null); }}
                style={{ fontSize: 10, padding: '2px 8px' }}
              >›</button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
