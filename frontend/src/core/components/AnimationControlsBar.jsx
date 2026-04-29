/**
 * AnimationControlsBar.jsx — transport controls + scrubber + options popover
 * for AnimationPane.
 *
 * Also exports small UI primitives (CtrlBtn, OptRow, OptPill) used only here.
 */

import React from 'react';
import { formatAnimTime } from './animationUtils';

// ── Sub-components ───────────────────────────────────────────────────────────

function CtrlBtn({ onClick, title, children }) {
  return (
    <button
      onClick={onClick}
      title={title}
      style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        height: 27, minWidth: 27, padding: '0 6px',
        background: '#161b22', border: '1px solid var(--bdL)',
        borderRadius: 4, color: 'var(--txD)', cursor: 'pointer',
        fontSize: 12, fontFamily: 'inherit',
      }}
      onMouseEnter={e => { e.currentTarget.style.borderColor = '#58a6ff'; e.currentTarget.style.color = 'var(--tx)'; }}
      onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--bdL)'; e.currentTarget.style.color = 'var(--txD)'; }}
    >
      {children}
    </button>
  );
}

function OptRow({ label, children }) {
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ fontSize: 9.5, color: 'var(--txDD)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 5 }}>{label}</div>
      <div style={{ display: 'flex', gap: 3, alignItems: 'center', flexWrap: 'wrap' }}>{children}</div>
    </div>
  );
}

function OptPill({ active, onClick, children }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: '2px 8px', height: 22,
        background: active ? 'rgba(88,166,255,0.08)' : '#0d1117',
        border: `1px solid ${active ? 'rgba(88,166,255,0.32)' : 'var(--bd)'}`,
        borderRadius: 3, color: active ? '#58a6ff' : 'var(--txDD)',
        cursor: 'pointer', fontFamily: 'inherit', fontSize: 10,
        display: 'flex', alignItems: 'center',
      }}
    >
      {children}
    </button>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function AnimationControlsBar({
  // transport
  animPlaying,
  animSpeed,
  animFrame,
  totalFrames,
  togglePlay,
  stepForward,
  stepBackward,
  goToStart,
  goToEnd,
  setAnimSpeed,
  // scrubber
  progressPct,
  handleScrubberClick,
  // event display
  currentTime,
  eventDesc,
  currentEvent,
  onSelectSession,
  selectEventLabel,
  // options popover
  animOpts,
  setAnimOpts,
  showOptions,
  setShowOptions,
  optionsRef,
  // hidden-node actions inside options
  animNodeMeta,
  visibleEdges,
  frameState,
  hiddenNodes,
  setHiddenNodes,
}) {
  const speeds = [0.5, 1, 2, 5];

  return (
    <div style={{
      background: 'var(--bgP)', borderTop: '1px solid var(--bd)',
      padding: '9px 14px 10px', flexShrink: 0, position: 'relative',
    }}>
      {/* Transport row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 9 }}>
        <CtrlBtn onClick={goToStart} title="First frame (Home)">⏮</CtrlBtn>
        <CtrlBtn onClick={stepBackward} title="Previous frame (←)">◀</CtrlBtn>
        <button
          onClick={togglePlay}
          title={animPlaying ? 'Pause (Space)' : 'Play (Space)'}
          style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            height: 27, padding: '0 12px', gap: 5, fontSize: 11,
            background: animPlaying ? '#1c2a1c' : '#1b3358',
            border: `1px solid ${animPlaying ? '#2f6830' : '#3670bf'}`,
            color: animPlaying ? '#3fb950' : '#6ab4ff',
            borderRadius: 4, cursor: 'pointer', fontFamily: 'inherit',
          }}
        >
          {animPlaying ? '⏸ Pause' : '▶ Play'}
        </button>
        <CtrlBtn onClick={stepForward} title="Next frame (→)">▶</CtrlBtn>
        <CtrlBtn onClick={goToEnd} title="Last frame (End)">⏭</CtrlBtn>
        <div style={{ width: 1, height: 20, background: 'var(--bd)', margin: '0 3px' }} />
        <div style={{ display: 'flex', gap: 2 }}>
          {speeds.map(s => (
            <button
              key={s}
              onClick={() => setAnimSpeed(s)}
              style={{
                padding: '2px 7px', height: 25,
                background: animSpeed === s ? 'rgba(88,166,255,0.09)' : '#161b22',
                border: `1px solid ${animSpeed === s ? 'rgba(88,166,255,0.32)' : 'var(--bd)'}`,
                borderRadius: 3, color: animSpeed === s ? '#58a6ff' : 'var(--txDD)',
                cursor: 'pointer', fontFamily: 'inherit', fontSize: 10,
              }}
            >
              {s}×
            </button>
          ))}
        </div>
        <div style={{ flex: 1 }} />
        {/* Options gear */}
        <div ref={optionsRef} style={{ position: 'relative' }}>
          <button
            onClick={() => setShowOptions(prev => !prev)}
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              width: 27, height: 25, background: showOptions ? '#161b22' : 'transparent',
              border: `1px solid ${showOptions ? 'var(--bdL)' : 'transparent'}`,
              borderRadius: 4, color: 'var(--txDD)', cursor: 'pointer', fontSize: 14,
            }}
            title="Options"
          >
            ⚙
          </button>
          {showOptions && (
            <div style={{
              position: 'absolute', bottom: 'calc(100% + 8px)', right: 0,
              background: '#161b22', border: '1px solid #30363d', borderRadius: 7,
              padding: '13px 15px', width: 255, boxShadow: '0 12px 36px rgba(0,0,0,0.7)', zIndex: 100,
            }}>
              <div style={{ fontSize: 9, fontWeight: 700, color: 'var(--txDD)', textTransform: 'uppercase', letterSpacing: '0.1em', paddingBottom: 9, marginBottom: 11, borderBottom: '1px solid var(--bd)' }}>
                Options
              </div>
              <OptRow label="Ended Sessions">
                <OptPill active={animOpts.endedMode === 'disappear'} onClick={() => setAnimOpts(o => ({ ...o, endedMode: 'disappear' }))}>Disappear</OptPill>
                <OptPill active={animOpts.endedMode === 'fade'} onClick={() => setAnimOpts(o => ({ ...o, endedMode: 'fade' }))}>Fade</OptPill>
                <OptPill active={animOpts.endedMode === 'color'} onClick={() => setAnimOpts(o => ({ ...o, endedMode: 'color' }))}>Color</OptPill>
              </OptRow>
              <OptRow label="Inactive Neighbours">
                <OptPill active={animOpts.showInactive} onClick={() => setAnimOpts(o => ({ ...o, showInactive: true }))}>Show</OptPill>
                <OptPill active={!animOpts.showInactive} onClick={() => setAnimOpts(o => ({ ...o, showInactive: false }))}>Hide</OptPill>
              </OptRow>
              <OptRow label="Edge Labels">
                <OptPill active={animOpts.edgeLabels === 'protocol'} onClick={() => setAnimOpts(o => ({ ...o, edgeLabels: 'protocol' }))}>Protocol</OptPill>
                <OptPill active={animOpts.edgeLabels === 'bytes'} onClick={() => setAnimOpts(o => ({ ...o, edgeLabels: 'bytes' }))}>Bytes</OptPill>
                <OptPill active={animOpts.edgeLabels === 'off'} onClick={() => setAnimOpts(o => ({ ...o, edgeLabels: 'off' }))}>Off</OptPill>
              </OptRow>
              <div style={{ borderTop: '1px solid var(--bd)', paddingTop: 9, marginTop: 2, display: 'flex', flexDirection: 'column', gap: 5 }}>
                <button
                  onClick={() => {
                    const inactive = Object.keys(animNodeMeta).filter(ip => {
                      if (animNodeMeta[ip]?.is_spotlight) return false;
                      return !visibleEdges.some(e => (e.src === ip || e.dst === ip) && frameState.active.has(e.session_id));
                    });
                    setHiddenNodes(prev => new Set([...prev, ...inactive]));
                  }}
                  style={{
                    padding: '5px 10px', background: 'rgba(248,81,73,0.06)',
                    border: '1px solid rgba(248,81,73,0.2)', borderRadius: 4,
                    color: '#f85149', cursor: 'pointer', fontFamily: 'inherit', fontSize: 10,
                    textAlign: 'left',
                  }}
                >
                  Hide all inactive neighbours
                </button>
                {hiddenNodes.size > 0 && (
                  <button
                    onClick={() => setHiddenNodes(new Set())}
                    style={{
                      padding: '5px 10px', background: 'rgba(63,185,80,0.06)',
                      border: '1px solid rgba(63,185,80,0.2)', borderRadius: 4,
                      color: '#3fb950', cursor: 'pointer', fontFamily: 'inherit', fontSize: 10,
                      textAlign: 'left',
                    }}
                  >
                    Restore all hidden ({hiddenNodes.size})
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Progress row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 11, marginBottom: 7 }}>
        <div
          onClick={handleScrubberClick}
          style={{ flex: 1, height: 4, background: '#161b22', borderRadius: 2, cursor: 'pointer', position: 'relative' }}
        >
          <div style={{
            height: '100%', background: 'linear-gradient(90deg, #1f4fa0, #58a6ff)',
            borderRadius: 2, pointerEvents: 'none', width: `${progressPct}%`,
          }} />
          <div style={{
            position: 'absolute', top: '50%', left: `${progressPct}%`,
            width: 10, height: 10, background: '#c9d1d9', borderRadius: '50%',
            transform: 'translate(-50%, -50%)',
            boxShadow: '0 0 0 2px #58a6ff, 0 0 6px rgba(88,166,255,0.4)',
            pointerEvents: 'none',
          }} />
        </div>
        <div style={{ fontSize: 10, color: 'var(--txDD)', whiteSpace: 'nowrap', minWidth: 195, textAlign: 'right' }}>
          Frame <b style={{ color: 'var(--txD)', fontWeight: 400 }}>{animFrame}</b> / {totalFrames}
          {' · '}{currentTime}
        </div>
      </div>

      {/* Event description */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, height: 17, overflow: 'hidden' }}>
        <span style={{ color: '#3670bf', fontSize: 10, flexShrink: 0 }}>❯</span>
        <span style={{ fontSize: 11, color: '#8b949e' }}>{eventDesc.text}</span>
        <span style={{
          fontSize: 10,
          color: eventDesc.cls === 'start' ? 'rgba(63,185,80,0.8)' : eventDesc.cls === 'end' ? 'rgba(248,81,73,0.7)' : 'var(--txDD)',
        }}>
          {eventDesc.detail}
        </span>
        {currentEvent && onSelectSession && (
          <button
            onClick={() => onSelectSession(currentEvent.session_id)}
            style={{
              padding: '1px 7px', height: 17, marginLeft: 4, flexShrink: 0,
              background: 'rgba(88,166,255,0.06)', border: '1px solid rgba(88,166,255,0.25)',
              borderRadius: 3, color: '#58a6ff', cursor: 'pointer',
              fontFamily: 'inherit', fontSize: 9.5, lineHeight: 1,
            }}
          >
            {selectEventLabel || 'View session'}
          </button>
        )}
      </div>
    </div>
  );
}
