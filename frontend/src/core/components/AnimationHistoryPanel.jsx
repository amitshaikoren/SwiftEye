/**
 * AnimationHistoryPanel.jsx — sliding event-history side panel for AnimationPane.
 *
 * Props:
 *   showHistory    — whether the panel is open
 *   visibleEvents  — filtered event list (respects focusedNode / hiddenNodes)
 *   animEvents     — full event list (for global frame-index lookup)
 *   animFrame      — current frame number
 *   totalFrames    — total frames in animation
 *   goToFrame      — (frame: number) => void
 */

import React, { useRef, useEffect } from 'react';
import { formatAnimTime } from './animationUtils';

export default function AnimationHistoryPanel({
  showHistory,
  visibleEvents,
  animEvents,
  animFrame,
  totalFrames,
  goToFrame,
}) {
  const historyListRef = useRef(null);

  // Auto-scroll to current event row
  useEffect(() => {
    if (!showHistory || !historyListRef.current) return;
    const el = historyListRef.current;
    const current = el.querySelector('.anim-hist-current');
    if (current) current.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }, [animFrame, showHistory]);

  return (
    <div style={{
      width: showHistory ? 248 : 0, overflow: 'hidden', background: 'var(--bgP)',
      borderLeft: '1px solid var(--bd)', display: 'flex', flexDirection: 'column',
      transition: 'width 0.22s ease', flexShrink: 0,
    }}>
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0 12px', height: 36, borderBottom: '1px solid var(--bd)', flexShrink: 0,
      }}>
        <div style={{ fontSize: 9.5, color: 'var(--txDD)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
          Event History
        </div>
        <div style={{ fontSize: 9, color: 'var(--txDD)' }}>
          {visibleEvents.length}{visibleEvents.length !== totalFrames ? `/${totalFrames}` : ''} events
        </div>
      </div>
      <div ref={historyListRef} style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden', padding: '4px 0' }}>
        {visibleEvents.map((ev, i) => {
          const globalIdx = animEvents.indexOf(ev) + 1;
          const isCurrent = globalIdx === animFrame;
          const isFuture = globalIdx > animFrame;
          return (
            <div
              key={i}
              className={isCurrent ? 'anim-hist-current' : ''}
              onClick={() => goToFrame(globalIdx)}
              style={{
                display: 'flex', alignItems: 'flex-start', gap: 8, padding: '5px 11px',
                cursor: isFuture ? 'default' : 'pointer',
                borderLeft: `2px solid ${isCurrent ? '#58a6ff' : 'transparent'}`,
                background: isCurrent ? 'rgba(88,166,255,0.06)' : 'transparent',
                opacity: isFuture ? 0.25 : 1,
                transition: 'background 0.1s',
              }}
              onMouseEnter={e => { if (!isFuture && !isCurrent) e.currentTarget.style.background = 'rgba(255,255,255,0.03)'; }}
              onMouseLeave={e => { if (!isFuture && !isCurrent) e.currentTarget.style.background = 'transparent'; }}
            >
              <div style={{ fontSize: 9, color: 'var(--txDD)', whiteSpace: 'nowrap', paddingTop: 1, flexShrink: 0 }}>
                {formatAnimTime(ev.time)}
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{
                  fontSize: 10.5, color: isCurrent ? 'var(--tx)' : '#8b949e',
                  lineHeight: 1.4, wordBreak: 'break-all',
                }}>
                  {ev.src} → {ev.dst}
                </div>
                <div style={{
                  display: 'inline-block', fontSize: 9, padding: '1px 5px', borderRadius: 3, marginTop: 2,
                  background: ev.type === 'start' ? 'rgba(63,185,80,0.12)' : 'rgba(248,81,73,0.1)',
                  color: ev.type === 'start' ? '#3fb950' : '#f85149',
                }}>
                  {ev.protocol} · {ev.type}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
