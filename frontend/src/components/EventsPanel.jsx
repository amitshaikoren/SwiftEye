/**
 * EventsPanel — right-side flagged events list (v0.21.0).
 *
 * Always visible inside InvestigationPage on both the Documentation tab
 * and the Timeline Graph tab. The list of cards is sorted by capture_time
 * ascending (with null/created_at fallback) so researchers see the
 * timeline order without having to switch to the graph tab.
 *
 * Phase 1 caveat banner: Events are session-only until the
 * `save-load-workspaces` roadmap item ships.
 */
import React, { useMemo } from 'react';
import EventCard from './EventCard';

export default function EventsPanel({
  events = [],
  onEventClick,         // (event) — highlight in main graph
  onEditEvent,
  onRemoveEvent,
  onCardDragStart,      // (e, event) — for drop targets
}) {
  const sorted = useMemo(() => {
    return [...events].sort((a, b) => {
      const ta = a.capture_time ?? a.created_at ?? 0;
      const tb = b.capture_time ?? b.created_at ?? 0;
      return ta - tb;
    });
  }, [events]);

  return (
    <div style={{
      width: 240,
      flexShrink: 0,
      borderLeft: '1px solid var(--bd)',
      background: 'var(--bgP)',
      display: 'flex', flexDirection: 'column',
      minHeight: 0,
    }}>
      {/* Header */}
      <div style={{
        padding: '8px 12px', borderBottom: '1px solid var(--bd)',
        background: 'var(--bgH)',
        display: 'flex', alignItems: 'center', gap: 6,
        flexShrink: 0,
      }}>
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#f85149" strokeWidth="2"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>
        <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--tx)', fontFamily: 'var(--fd)' }}>
          Flagged Events
        </div>
        <div style={{ flex: 1 }} />
        <div style={{ fontSize: 9, color: 'var(--txD)' }}>
          {events.length}
        </div>
      </div>

      {/* Caveat banner */}
      <div style={{
        padding: '5px 10px',
        background: 'rgba(208,153,34,.08)',
        borderBottom: '1px solid var(--bd)',
        fontSize: 9, color: 'var(--txD)', lineHeight: 1.35,
        flexShrink: 0,
      }}>
        Beta · session-only until workspace save ships
      </div>

      {/* Body */}
      <div style={{ flex: 1, overflow: 'auto', padding: 8 }}>
        {events.length === 0 ? (
          <div style={{
            fontSize: 10, color: 'var(--txD)',
            padding: '24px 12px', textAlign: 'center', lineHeight: 1.6,
          }}>
            No events yet.<br/>
            Right-click a node or edge in the graph and choose <b>Flag as Event</b>, or use the <b>Flag</b> button in Session Detail.
          </div>
        ) : (
          sorted.map(ev => (
            <EventCard
              key={ev.id}
              event={ev}
              isPlaced={ev.canvas_x != null && ev.canvas_y != null}
              onClick={() => onEventClick?.(ev)}
              onEdit={() => onEditEvent?.(ev)}
              onRemove={() => onRemoveEvent?.(ev)}
              onDragStart={onCardDragStart}
            />
          ))
        )}
      </div>
    </div>
  );
}
