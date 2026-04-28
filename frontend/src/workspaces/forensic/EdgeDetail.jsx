import { useState, useCallback, useEffect, useMemo } from 'react';
import Tag from '../../core/components/Tag';
import Row from '../../core/components/Row';
import Collapse from '../../core/components/Collapse';
import { useWorkspace } from '@/WorkspaceProvider';
import ForensicEventDetail from './EventDetail';

// ── Helpers ───────────────────────────────────────────────────────────────────

function actionLabel(at) {
  if (!at) return '';
  return at.split('_').map(s => s ? s[0].toUpperCase() + s.slice(1) : '').join(' ');
}

function ActionBadge({ action, color }) {
  const label = actionLabel(action);
  const c = color || '#8b949e';
  return (
    <span style={{
      fontSize: 9, padding: '1px 6px', borderRadius: 6,
      background: c + '22', color: c, border: '1px solid ' + c + '44',
      fontWeight: 600, whiteSpace: 'nowrap', letterSpacing: '0.04em', flexShrink: 0,
    }}>{label || action}</span>
  );
}

function formatTs(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC'); }
  catch { return iso; }
}

function formatDuration(first, last) {
  if (!first || !last) return null;
  const ms = new Date(last) - new Date(first);
  if (ms <= 0) return null;
  if (ms < 1000) return ms + 'ms';
  if (ms < 60000) return (ms / 1000).toFixed(1) + 's';
  return Math.round(ms / 60000) + 'm ' + Math.round((ms % 60000) / 1000) + 's';
}

// ── Event row (list view) ─────────────────────────────────────────────────────

function EventRow({ ev, actionColor, onClick }) {
  const hasFields = ev.fields && Object.keys(ev.fields).length > 0;
  // Show a short summary hint under the timestamp
  const hint = ev.fields?.command_line
    ? ev.fields.command_line.slice(0, 60) + (ev.fields.command_line.length > 60 ? '…' : '')
    : ev.fields?.details
    ? ev.fields.details.slice(0, 60) + (ev.fields.details.length > 60 ? '…' : '')
    : ev.fields?.protocol
    ? ev.fields.protocol
    : null;

  return (
    <div
      className="hr"
      onClick={onClick}
      style={{
        borderBottom: '1px solid var(--bd)', padding: '8px 2px',
        cursor: 'pointer', borderRadius: 3,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <ActionBadge action={ev.action_type} color={actionColor} />
        <span style={{ fontSize: 10, color: 'var(--txD)', fontFamily: 'var(--fn)', flex: 1 }}>
          {formatTs(ev.ts)}
        </span>
        {hasFields && (
          <span style={{ fontSize: 9, color: 'var(--txD)', flexShrink: 0 }}>›</span>
        )}
      </div>
      {hint && (
        <div style={{
          fontSize: 9, color: 'var(--txD)', marginTop: 3, paddingLeft: 2,
          fontFamily: 'var(--fn)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>{hint}</div>
      )}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

const PAGE = 50;

export default function ForensicEdgeDetail({ edge, onClear, nodes = [], annotations = [], onSaveNote }) {
  const workspace = useWorkspace();
  const [page, setPage] = useState(0);
  const [selEvent, setSelEvent] = useState(null);

  // Edge-type schema lookup
  const edgeMetaByName = useMemo(() => {
    const m = {};
    for (const et of (workspace.schema?.edge_types || [])) m[et.name] = et;
    return m;
  }, [workspace.schema]);

  const actionToEdgeType = workspace.actionTypeToEdgeType || {};
  function colorForAction(action) {
    const edgeName = actionToEdgeType[action];
    return edgeName ? (edgeMetaByName[edgeName]?.color || null) : null;
  }

  // Notes
  const edgeId = edge?.id || '';
  const existingNote = annotations.find(a => a.annotation_type === 'note' && a.edge_id === edgeId);
  const [noteText, setNoteText] = useState(existingNote?.text || '');
  const [noteSaved, setNoteSaved] = useState(false);
  useEffect(() => { setNoteText(existingNote?.text || ''); setNoteSaved(false); }, [edgeId, annotations]);
  const saveNote = useCallback(async () => {
    if (onSaveNote) {
      await onSaveNote(edgeId, noteText, existingNote?.id, 'edge_id');
      setNoteSaved(true);
      setTimeout(() => setNoteSaved(false), 1500);
    }
  }, [edgeId, noteText, existingNote, onSaveNote]);

  // Reset state when edge changes
  useEffect(() => { setPage(0); setSelEvent(null); }, [edgeId]);

  if (!edge) return null;

  const events = edge.events || [];
  const total  = events.length;
  const start  = page * PAGE;
  const pageEvents = events.slice(start, start + PAGE);
  const pages  = Math.ceil(total / PAGE);

  const srcId = typeof edge.source === 'object' ? edge.source.id : edge.source;
  const dstId = typeof edge.target === 'object' ? edge.target.id : edge.target;
  const srcNode = nodes.find(n => n.id === srcId);
  const dstNode = nodes.find(n => n.id === dstId);
  const srcLabel = srcNode?.label || srcNode?.image || srcId;
  const dstLabel = dstNode?.label || dstNode?.image || dstId;

  const headerMeta = edgeMetaByName[edge.type] || null;
  const edgeColor  = headerMeta?.color || '#8b949e';
  const edgeLabel  = headerMeta?.label || edge.type || 'edge';
  const duration   = formatDuration(edge.ts_first, edge.ts_last);

  const edgeContext = { srcLabel, dstLabel, edgeType: edge.type, edgeColor };

  // ── Event detail view ────────────────────────────────────────────────────────
  if (selEvent !== null) {
    return (
      <ForensicEventDetail
        event={selEvent}
        events={events}
        edgeContext={edgeContext}
        onBack={() => setSelEvent(null)}
        annotations={annotations}
        onSaveNote={onSaveNote}
      />
    );
  }

  // ── Edge list view ───────────────────────────────────────────────────────────
  return (
    <div className="fi" style={{ padding: 16, overflowY: 'auto', height: '100%' }}>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <div className="sh" style={{ marginBottom: 0 }}>Edge Detail</div>
        <button className="btn" onClick={onClear}>✕</button>
      </div>

      {/* Edge type badge */}
      <div style={{ marginBottom: 10 }}>
        <Tag color={edgeColor}>{edgeLabel}</Tag>
      </div>

      {/* Relationship hero: src → dst */}
      <div style={{
        background: 'var(--bgC)', border: '1px solid var(--bd)', borderRadius: 5,
        padding: '8px 10px', marginBottom: 10,
        display: 'flex', alignItems: 'center', gap: 6,
      }}>
        <span style={{
          fontSize: 10, color: 'var(--txM)', flex: 1, overflow: 'hidden',
          textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }} title={srcId}>{srcLabel}</span>
        <span style={{ color: edgeColor, fontSize: 12, flexShrink: 0 }}>→</span>
        <span style={{
          fontSize: 10, color: 'var(--txM)', flex: 1, overflow: 'hidden',
          textOverflow: 'ellipsis', whiteSpace: 'nowrap', textAlign: 'right',
        }} title={dstId}>{dstLabel}</span>
      </div>

      {/* Summary */}
      <Row l="Events"      v={String(total)} />
      {edge.ts_first && <Row l="First seen" v={formatTs(edge.ts_first)} />}
      {edge.ts_last  && <Row l="Last seen"  v={formatTs(edge.ts_last)} />}
      {duration      && <Row l="Duration"   v={duration} />}

      {/* Events list */}
      <Collapse title={`Events (${total})`} open>
        {total === 0 ? (
          <div style={{ color: 'var(--txD)', fontSize: 11 }}>No events on this edge.</div>
        ) : (
          <>
            {pageEvents.map((ev, i) => (
              <EventRow
                key={start + i}
                ev={ev}
                actionColor={colorForAction(ev.action_type)}
                onClick={() => setSelEvent(ev)}
              />
            ))}
            {pages > 1 && (
              <div style={{ display: 'flex', gap: 6, marginTop: 8, justifyContent: 'center', alignItems: 'center' }}>
                <button
                  className="btn" disabled={page === 0}
                  onClick={() => setPage(p => p - 1)}
                  style={{ fontSize: 10, padding: '2px 8px' }}
                >‹</button>
                <span style={{ fontSize: 10, color: 'var(--txD)' }}>{page + 1} / {pages}</span>
                <button
                  className="btn" disabled={page >= pages - 1}
                  onClick={() => setPage(p => p + 1)}
                  style={{ fontSize: 10, padding: '2px 8px' }}
                >›</button>
              </div>
            )}
          </>
        )}
      </Collapse>

      {/* Notes */}
      <Collapse title="Notes" open={!!noteText}>
        <textarea
          value={noteText}
          onChange={e => setNoteText(e.target.value)}
          placeholder="Add investigation notes…"
          rows={3}
          style={{
            width: '100%', boxSizing: 'border-box',
            background: 'var(--bgC)', border: '1px solid var(--bd)', borderRadius: 4,
            padding: '6px 8px', fontSize: 10, color: 'var(--txM)',
            fontFamily: 'inherit', resize: 'vertical', outline: 'none', lineHeight: 1.5,
          }}
        />
        <button
          className="btn"
          onClick={saveNote}
          style={{
            fontSize: 9, padding: '2px 12px', marginTop: 5, width: '100%',
            background: noteSaved ? 'rgba(63,185,80,.15)' : undefined,
            color: noteSaved ? 'var(--acG)' : undefined,
            borderColor: noteSaved ? 'var(--acG)' : undefined,
          }}
        >{noteSaved ? '✓ Saved' : 'Save note'}</button>
      </Collapse>

    </div>
  );
}
