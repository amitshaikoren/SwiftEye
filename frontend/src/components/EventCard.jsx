/**
 * EventCard — single Event in the Flagged Events panel (v0.21.0).
 *
 * Renders a compact card per Event with severity ring, title, target, and
 * a kebab menu for edit/remove. Drag handle is the whole card; consumers
 * (markdown editor, TimelineGraph) read the dataTransfer payload to know
 * which event was dropped where.
 */
import React, { useState } from 'react';
import { SEVERITY_COLOR } from '../hooks/useEvents';

const ENTITY_ICON = {
  node:    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="9"/></svg>,
  edge:    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="13 6 19 12 13 18"/></svg>,
  session: <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="6" width="18" height="12" rx="2"/></svg>,
};

function targetLine(ev) {
  if (ev.entity_type === 'node')    return ev.node_id;
  if (ev.entity_type === 'edge')    return ev.edge_id;
  if (ev.entity_type === 'session') return `session ${(ev.session_id || '').slice(0, 8)}`;
  return '';
}

export default function EventCard({
  event,
  onClick,         // body click — highlight in main graph
  onEdit,          // open edit modal
  onRemove,        // unflag
  onDragStart,     // (e, event) — caller sets dataTransfer
  isPlaced,        // bool: already placed on the timeline canvas
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const sevColor = SEVERITY_COLOR[event.severity] || 'var(--bd)';

  return (
    <div
      draggable
      onDragStart={e => {
        e.dataTransfer.setData('application/x-swifteye-event', event.id);
        e.dataTransfer.effectAllowed = 'copyMove';
        onDragStart?.(e, event);
      }}
      onClick={onClick}
      style={{
        background: 'rgba(255,255,255,.045)',
        border: '1px solid rgba(255,255,255,.14)',
        borderLeft: `3px solid ${sevColor}`,
        borderRadius: 4,
        padding: '7px 9px',
        marginBottom: 6,
        cursor: 'grab',
        position: 'relative',
        opacity: isPlaced ? 0.55 : 1,
        boxShadow: '0 1px 2px rgba(0,0,0,.25)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
        <span style={{ color: sevColor, display: 'flex', alignItems: 'center' }}>{ENTITY_ICON[event.entity_type]}</span>
        <div style={{
          fontSize: 11, fontWeight: 600, color: 'var(--tx)',
          flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>
          {event.title}
        </div>
        <button
          className="btn"
          onClick={e => { e.stopPropagation(); setMenuOpen(o => !o); }}
          style={{ fontSize: 9, padding: '0 6px', lineHeight: 1.4 }}
          title="More"
        >⋯</button>
      </div>
      <div style={{
        fontSize: 9, color: 'var(--txD)', fontFamily: 'var(--fn)',
        marginTop: 2, marginLeft: 16,
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
      }}>
        {targetLine(event)}
      </div>
      {event.description && (
        <div style={{
          fontSize: 10, color: 'var(--txM)', marginTop: 4, marginLeft: 16,
          lineHeight: 1.4,
          display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical',
          overflow: 'hidden',
        }}>
          {event.description}
        </div>
      )}
      {isPlaced && (
        <div style={{
          position: 'absolute', top: 4, right: 26,
          fontSize: 8, color: 'var(--txD)', fontStyle: 'italic',
        }}>placed</div>
      )}

      {menuOpen && (
        <>
          <div onClick={() => setMenuOpen(false)}
            style={{ position: 'fixed', inset: 0, zIndex: 99 }} />
          <div style={{
            position: 'absolute', top: 22, right: 4, zIndex: 100,
            background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 4,
            boxShadow: '0 4px 12px rgba(0,0,0,.4)',
            display: 'flex', flexDirection: 'column', minWidth: 110,
          }}>
            <button className="btn" style={{ fontSize: 10, padding: '5px 10px', textAlign: 'left', borderRadius: 0, border: 'none' }}
              onClick={e => { e.stopPropagation(); setMenuOpen(false); onEdit?.(event); }}
            >Edit</button>
            <button className="btn" style={{ fontSize: 10, padding: '5px 10px', textAlign: 'left', borderRadius: 0, border: 'none', color: '#f85149' }}
              onClick={e => { e.stopPropagation(); setMenuOpen(false); onRemove?.(event); }}
            >Remove flag</button>
          </div>
        </>
      )}
    </div>
  );
}
