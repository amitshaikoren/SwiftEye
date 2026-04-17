/**
 * AnimationPane — coordinator for the temporal animation view.
 *
 * Replaces GraphCanvas when animActive === true.
 *
 * Modules:
 *   animationUtils.js        — constants + pure helpers
 *   useAnimationCanvas.js    — canvas setup, zoom, fit, render loop
 *   useAnimationInteraction.js — click/hover, drag, keyboard, popovers
 *   AnimationHistoryPanel.jsx — sliding event-history side panel
 *   AnimationControlsBar.jsx  — transport + scrubber + options popover
 */

import React, { useRef, useCallback, useState, useMemo } from 'react';
import { fB, fN } from '../utils';
import { useFilterContext } from '../FilterContext';
import {
  buildSessionMap,
  buildEdgeList,
  formatAnimTime,
} from './animationUtils';
import { useAnimationCanvas } from './useAnimationCanvas';
import { useAnimationInteraction } from './useAnimationInteraction';
import AnimationHistoryPanel from './AnimationHistoryPanel';
import AnimationControlsBar from './AnimationControlsBar';

export default function AnimationPane({
  // Animation state (from useCapture → useAnimationMode)
  animNodes, animEvents, animNodeMeta, animFrame, animPlaying, animSpeed,
  animOpts, frameState, currentEvent, animTimeRange, totalFrames, isIsolated,
  // Actions
  togglePlay, goToFrame, stepForward, stepBackward, goToStart, goToEnd,
  setAnimSpeed, setAnimOpts, stopAnimation, setIsIsolated,
  // External data for positioning
  mainNodes, pColors,
  // Persisted positions — survives full-width panel switches (Research, Timeline…)
  savedPositionsRef,
  // Click handlers for detail panels
  onSelectNode, onSelectSession,
}) {
  // ── Shared refs (passed to hooks) ─────────────────────────────────
  const canvasRef = useRef(null);
  const wrapRef = useRef(null);
  const positionsRef = useRef({});
  const transformRef = useRef({ x: 0, y: 0, k: 1 });
  const zoomRef = useRef(null);
  const flashRef = useRef({});
  const optionsRef = useRef(null);

  // ── UI state ──────────────────────────────────────────────────────
  const [showHistory, setShowHistory] = useState(false);
  const [showOptions, setShowOptions] = useState(false);
  const [hovered, setHovered] = useState(null); // { type: 'node'|'edge', id, x, y }
  const [focusedNode, setFocusedNode] = useState(null); // null = all, IP = spotlight filter
  const [hiddenNodes, setHiddenNodes] = useState(new Set());
  const [contextMenu, setContextMenu] = useState(null); // { x, y, ip }

  // ── Derived data ──────────────────────────────────────────────────
  const sessionMap = useMemo(() => buildSessionMap(animEvents), [animEvents]);
  const edgeList = useMemo(() => buildEdgeList(sessionMap), [sessionMap]);
  const filterCtx = useFilterContext();

  // Filtered edges: protocol filter + focusedNode + hiddenNodes.
  // When isIsolated is on, the event list is already filtered upstream
  // in useAnimationMode, so edgeList only contains spotlight↔spotlight sessions.
  const visibleEdges = useMemo(() => {
    const { enabledP, allProtocolKeysCount } = filterCtx;
    const noneSelected = enabledP.size === 0 && allProtocolKeysCount > 0;
    const someFiltered = enabledP.size > 0 && enabledP.size < allProtocolKeysCount;
    const appProtos = someFiltered
      ? new Set([...enabledP].map(k => k.split('/').pop().toUpperCase()))
      : null;

    return edgeList.filter(e => {
      if (noneSelected) return false;
      if (appProtos && !appProtos.has((e.protocol || '').toUpperCase())) return false;
      if (focusedNode && e.src !== focusedNode && e.dst !== focusedNode) return false;
      if (hiddenNodes.has(e.src) || hiddenNodes.has(e.dst)) return false;
      return true;
    });
  }, [edgeList, focusedNode, hiddenNodes, filterCtx]);

  const visibleEvents = useMemo(() => {
    if (!focusedNode && hiddenNodes.size === 0) return animEvents;
    const visibleSids = new Set(visibleEdges.map(e => e.session_id));
    return animEvents.filter(ev => visibleSids.has(ev.session_id));
  }, [animEvents, visibleEdges, focusedNode, hiddenNodes]);

  // ── Canvas hook ───────────────────────────────────────────────────
  useAnimationCanvas({
    canvasRef, wrapRef, positionsRef, transformRef, zoomRef, flashRef,
    animNodeMeta, mainNodes, currentEvent, animNodes, animOpts, pColors,
    visibleEdges, frameState, hiddenNodes, animEvents,
    savedPositionsRef,
  });

  // ── Interaction hook ──────────────────────────────────────────────
  const {
    handleCanvasEvent,
    handleContextMenu,
    handleDragStart,
    handleDragMove,
    handleDragEnd,
  } = useAnimationInteraction({
    canvasRef, positionsRef, transformRef, zoomRef, optionsRef,
    hiddenNodes, frameState, visibleEdges, contextMenu, showOptions,
    setShowOptions, setContextMenu, setHovered,
    onSelectNode, onSelectSession,
    togglePlay, stepForward, stepBackward, goToStart, goToEnd, stopAnimation,
    savedPositionsRef,
  });

  // ── Computed display values ───────────────────────────────────────
  const currentTime = currentEvent
    ? formatAnimTime(currentEvent.time)
    : formatAnimTime(animTimeRange.min);
  const progressPct = totalFrames > 0 ? (animFrame / totalFrames) * 100 : 0;

  const watchLabel = useMemo(() => {
    if (animNodes.length <= 3) return animNodes.join(', ');
    return animNodes.slice(0, 3).join(', ') + ` [+${animNodes.length - 3} more]`;
  }, [animNodes]);

  const neighbourCount = useMemo(() => {
    return Object.keys(animNodeMeta).filter(ip => !animNodeMeta[ip]?.is_spotlight).length;
  }, [animNodeMeta]);

  const eventDesc = useMemo(() => {
    if (!currentEvent) return { text: 'Ready', detail: '', cls: 'init' };
    const arrow = currentEvent.type === 'start' ? '──▶' : '──×';
    const text = `${currentEvent.src} ─[${currentEvent.protocol}]${arrow} ${currentEvent.dst}`;
    const detail = currentEvent.type === 'start' ? 'new session' : 'session ended';
    return { text, detail, cls: currentEvent.type };
  }, [currentEvent]);

  const handleScrubberClick = useCallback((e) => {
    const bar = e.currentTarget;
    const rect = bar.getBoundingClientRect();
    const frac = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
    const frame = Math.round(frac * totalFrames);
    goToFrame(frame);
  }, [totalFrames, goToFrame]);

  // ── Render ────────────────────────────────────────────────────────
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--bg)', fontFamily: 'JetBrains Mono, ui-monospace, monospace', fontSize: 12 }}>
      {/* ── Header ─────────────────────────────────────────────────── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 12, padding: '0 14px', height: 44,
        background: 'var(--bgP)', borderBottom: '1px solid var(--bd)', flexShrink: 0,
      }}>
        <div style={{
          display: 'flex', alignItems: 'center', gap: 6, padding: '3px 10px',
          background: 'rgba(88,166,255,0.08)', border: '1px solid rgba(88,166,255,0.28)',
          borderRadius: 4, color: '#6ab4ff', fontSize: 9.5, fontWeight: 700,
          letterSpacing: '0.12em', textTransform: 'uppercase', flexShrink: 0,
        }}>
          <div style={{
            width: 5, height: 5, borderRadius: '50%', background: '#58a6ff',
            animation: 'animPulse 2s ease-in-out infinite',
          }} />
          Animation
        </div>
        <div style={{ color: 'var(--txD)', fontSize: 11, flex: 1, display: 'flex', alignItems: 'center', gap: 8, overflow: 'hidden' }}>
          {animNodes.length > 1 ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 3, flexShrink: 0 }}>
              <span style={{ color: 'var(--txD)', fontSize: 10, marginRight: 2 }}>Focus:</span>
              <FocusPill active={!focusedNode} onClick={() => setFocusedNode(null)}>All</FocusPill>
              {animNodes.map(ip => (
                <FocusPill key={ip} active={focusedNode === ip} onClick={() => setFocusedNode(ip)}>
                  {animNodeMeta[ip]?.hostname || ip}
                </FocusPill>
              ))}
            </div>
          ) : (
            <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              Watching: <strong style={{ color: '#c9d1d9', fontWeight: 500 }}>{watchLabel}</strong>
            </span>
          )}
          {neighbourCount > 0 && <span style={{ flexShrink: 0 }}> · {neighbourCount} neighbours</span>}
          {hiddenNodes.size > 0 && (
            <HiddenBadge count={hiddenNodes.size} onRestoreAll={() => setHiddenNodes(new Set())} />
          )}
        </div>
        <button
          onClick={() => setIsIsolated(prev => !prev)}
          title="Show only traffic between spotlight nodes"
          style={{
            padding: '4px 11px', height: 28, background: isIsolated ? 'rgba(210,153,34,0.10)' : 'transparent',
            border: `1px solid ${isIsolated ? 'rgba(210,153,34,0.45)' : 'var(--bdL)'}`,
            color: isIsolated ? '#d29922' : 'var(--txD)', borderRadius: 4, cursor: 'pointer',
            fontFamily: 'inherit', fontSize: 10.5, flexShrink: 0,
          }}
        >
          {isIsolated ? '⊙ Isolated' : '⊙ Isolate'}
        </button>
        <button
          onClick={() => setShowHistory(prev => !prev)}
          style={{
            padding: '4px 11px', height: 28, background: showHistory ? 'rgba(88,166,255,0.07)' : 'transparent',
            border: `1px solid ${showHistory ? 'rgba(88,166,255,0.35)' : 'var(--bdL)'}`,
            color: showHistory ? '#58a6ff' : 'var(--txD)', borderRadius: 4, cursor: 'pointer',
            fontFamily: 'inherit', fontSize: 10.5, flexShrink: 0,
          }}
        >
          History
        </button>
        <button
          onClick={stopAnimation}
          style={{
            padding: '4px 11px', height: 28, background: 'transparent',
            border: '1px solid var(--bdL)', color: 'var(--txD)', borderRadius: 4,
            cursor: 'pointer', fontFamily: 'inherit', fontSize: 10.5, flexShrink: 0,
          }}
          onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(248,81,73,0.4)'; e.currentTarget.style.color = '#f85149'; }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--bdL)'; e.currentTarget.style.color = 'var(--txD)'; }}
        >
          ✕ Exit
        </button>
      </div>

      {/* ── Main area ──────────────────────────────────────────────── */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden', position: 'relative' }}>
        {/* Canvas */}
        <div ref={wrapRef} style={{ flex: 1, position: 'relative', overflow: 'hidden', background: 'var(--bg)' }}>
          <canvas
            ref={canvasRef}
            onClick={handleCanvasEvent}
            onMouseMove={(e) => { handleDragMove(e); handleCanvasEvent(e); }}
            onPointerDown={handleDragStart}
            onPointerUp={handleDragEnd}
            onPointerCancel={handleDragEnd}
            onContextMenu={handleContextMenu}
            style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }}
          />

          {/* Legend (top-left) */}
          <div style={{
            position: 'absolute', top: 12, left: 12, background: 'rgba(13,17,23,0.9)',
            border: '1px solid var(--bd)', borderRadius: 6, padding: '8px 11px',
            fontSize: 10, pointerEvents: 'none', backdropFilter: 'blur(4px)',
          }}>
            <div style={{ color: 'var(--txDD)', textTransform: 'uppercase', letterSpacing: '0.08em', fontSize: 9, marginBottom: 6 }}>Legend</div>
            {(() => {
              const protos = new Set();
              for (const e of visibleEdges) {
                if (frameState.active.has(e.session_id) || frameState.ended.has(e.session_id)) {
                  protos.add(e.protocol);
                }
              }
              return [...protos].sort().map(p => (
                <div key={p} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3.5, color: 'var(--txD)' }}>
                  <div style={{ width: 18, height: 2.5, borderRadius: 2, background: pColors[p] || '#64748b', flexShrink: 0 }} />
                  {p}
                </div>
              ));
            })()}
            <div style={{ height: 6 }} />
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3.5, color: 'var(--txD)' }}>
              <div style={{ width: 9, height: 9, borderRadius: '50%', background: '#264060', border: '1.5px solid #58a6ff', flexShrink: 0 }} />
              Spotlight
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3.5, color: 'var(--txD)' }}>
              <div style={{ width: 9, height: 9, borderRadius: '50%', background: '#264060', border: '1.5px solid #5a9ad5', flexShrink: 0 }} />
              Private
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--txD)' }}>
              <div style={{ width: 9, height: 9, borderRadius: '50%', background: '#3d2855', border: '1.5px solid #9060cc', flexShrink: 0 }} />
              External
            </div>
          </div>

          {/* Frame overlay (top-right) */}
          <div style={{
            position: 'absolute', top: 12, right: showHistory ? 260 : 12,
            background: 'rgba(13,17,23,0.88)', border: '1px solid var(--bd)',
            borderRadius: 6, padding: '6px 11px', pointerEvents: 'none', textAlign: 'right',
            backdropFilter: 'blur(4px)', transition: 'right 0.22s ease',
          }}>
            <div style={{ color: '#8b949e', fontSize: 11.5, letterSpacing: '0.02em' }}>{currentTime}</div>
            <div style={{ color: 'var(--txDD)', fontSize: 10, marginTop: 2 }}>
              Active: <b style={{ color: 'var(--txD)', fontWeight: 400 }}>{frameState.active.size}</b>
              {' · '}Ended: <b style={{ color: 'var(--txD)', fontWeight: 400 }}>{frameState.ended.size}</b>
            </div>
          </div>

          {/* Context menu */}
          {contextMenu && (
            <div style={{
              position: 'fixed', left: contextMenu.x, top: contextMenu.y,
              background: '#161b22', border: '1px solid #30363d', borderRadius: 6,
              padding: '4px 0', boxShadow: '0 8px 24px rgba(0,0,0,0.6)', zIndex: 1000,
              minWidth: 160, fontFamily: 'inherit',
            }}>
              <div style={{ padding: '3px 12px', fontSize: 9, color: 'var(--txDD)', textTransform: 'uppercase', letterSpacing: '.06em' }}>
                {contextMenu.ip}
              </div>
              <div style={{ height: 1, background: 'var(--bd)', margin: '3px 0' }} />
              {animNodeMeta[contextMenu.ip]?.is_spotlight && animNodes.length > 1 && (
                <div
                  onClick={() => { setFocusedNode(focusedNode === contextMenu.ip ? null : contextMenu.ip); setContextMenu(null); }}
                  style={{ padding: '6px 12px', fontSize: 11, color: 'var(--txM)', cursor: 'pointer' }}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,.06)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  {focusedNode === contextMenu.ip ? 'Show all nodes' : 'Focus on this node'}
                </div>
              )}
              <div
                onClick={() => { setHiddenNodes(prev => new Set([...prev, contextMenu.ip])); setContextMenu(null); }}
                style={{ padding: '6px 12px', fontSize: 11, color: 'var(--txM)', cursor: 'pointer' }}
                onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,.06)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              >
                <span style={{ marginRight: 6, fontSize: 10, opacity: 0.5 }}>
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ verticalAlign: '-1px' }}>
                    <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19M1 1l22 22" />
                  </svg>
                </span>
                Hide node
              </div>
              {onSelectNode && (
                <div
                  onClick={() => { onSelectNode(contextMenu.ip); setContextMenu(null); }}
                  style={{ padding: '6px 12px', fontSize: 11, color: 'var(--txM)', cursor: 'pointer' }}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,.06)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  View details
                </div>
              )}
            </div>
          )}

          {/* Tooltip */}
          {hovered && (
            <div style={{
              position: 'fixed', left: hovered.x + 12, top: hovered.y - 10,
              pointerEvents: 'none', background: 'rgba(13,17,23,0.97)',
              border: '1px solid #30363d', borderRadius: 6, padding: '7px 11px',
              fontSize: 11, lineHeight: 1.65, color: 'var(--tx)', zIndex: 999,
              maxWidth: 240, boxShadow: '0 8px 24px rgba(0,0,0,0.6)',
            }}>
              {hovered.type === 'node' ? (() => {
                const meta = animNodeMeta[hovered.id] || {};
                return <>
                  <div style={{ color: '#58a6ff', fontWeight: 700, fontSize: 11.5, marginBottom: 3 }}>{hovered.id}</div>
                  {meta.hostname && <div style={{ color: '#3fb950', fontSize: 10, marginBottom: 3 }}>{meta.hostname}</div>}
                  <div style={{ color: '#8b949e' }}>{meta.is_private ? 'Private' : 'External'}{meta.is_spotlight ? ' · Spotlight' : ''}</div>
                  <div style={{ color: '#8b949e' }}>{fB(meta.bytes)} · {fN(meta.packets)} pkts</div>
                  <div style={{ color: '#8b949e' }}>
                    Active: {[...frameState.active].filter(sid => {
                      const s = sessionMap[sid];
                      return s && (s.src === hovered.id || s.dst === hovered.id);
                    }).length}
                  </div>
                </>;
              })() : (() => {
                const ev = sessionMap[hovered.id];
                if (!ev) return null;
                const isActive = frameState.active.has(hovered.id);
                return <>
                  <div style={{ color: pColors[ev.protocol] || '#64748b', fontWeight: 700, fontSize: 11.5, marginBottom: 3 }}>{ev.protocol}</div>
                  <div style={{ color: '#8b949e' }}>{ev.src} → {ev.dst}</div>
                  <div style={{ color: '#8b949e' }}>{fB(ev.bytes)} · {fN(ev.packets)} pkts</div>
                  <div style={{
                    display: 'inline-block', fontSize: 9.5, padding: '1px 6px', borderRadius: 3, marginTop: 3,
                    background: isActive ? 'rgba(63,185,80,0.15)' : 'rgba(136,136,136,0.12)',
                    color: isActive ? '#3fb950' : '#768390',
                  }}>{isActive ? 'Active' : 'Ended'}</div>
                </>;
              })()}
            </div>
          )}
        </div>

        {/* History panel */}
        <AnimationHistoryPanel
          showHistory={showHistory}
          visibleEvents={visibleEvents}
          animEvents={animEvents}
          animFrame={animFrame}
          totalFrames={totalFrames}
          goToFrame={goToFrame}
        />
      </div>

      {/* Controls bar */}
      <AnimationControlsBar
        animPlaying={animPlaying}
        animSpeed={animSpeed}
        animFrame={animFrame}
        totalFrames={totalFrames}
        togglePlay={togglePlay}
        stepForward={stepForward}
        stepBackward={stepBackward}
        goToStart={goToStart}
        goToEnd={goToEnd}
        setAnimSpeed={setAnimSpeed}
        progressPct={progressPct}
        handleScrubberClick={handleScrubberClick}
        currentTime={currentTime}
        eventDesc={eventDesc}
        currentEvent={currentEvent}
        onSelectSession={onSelectSession}
        animOpts={animOpts}
        setAnimOpts={setAnimOpts}
        showOptions={showOptions}
        setShowOptions={setShowOptions}
        optionsRef={optionsRef}
        animNodeMeta={animNodeMeta}
        visibleEdges={visibleEdges}
        frameState={frameState}
        hiddenNodes={hiddenNodes}
        setHiddenNodes={setHiddenNodes}
      />

      {/* Pulse keyframe */}
      <style>{`@keyframes animPulse { 0%,100%{opacity:1} 50%{opacity:0.2} }`}</style>
    </div>
  );
}

// ── Sub-components used only in this file ────────────────────────────────────

function FocusPill({ active, onClick, children }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: '2px 8px', height: 22,
        background: active ? 'rgba(88,166,255,0.12)' : 'transparent',
        border: `1px solid ${active ? 'rgba(88,166,255,0.35)' : 'var(--bd)'}`,
        borderRadius: 4, color: active ? '#58a6ff' : 'var(--txDD)',
        cursor: 'pointer', fontFamily: 'inherit', fontSize: 10,
        whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
        maxWidth: 140,
      }}
    >
      {children}
    </button>
  );
}

function HiddenBadge({ count, onRestoreAll }) {
  return (
    <button
      onClick={onRestoreAll}
      title="Click to restore all hidden nodes"
      style={{
        display: 'flex', alignItems: 'center', gap: 4,
        padding: '2px 8px', height: 22, flexShrink: 0,
        background: 'rgba(248,81,73,0.08)', border: '1px solid rgba(248,81,73,0.25)',
        borderRadius: 4, color: '#f85149', cursor: 'pointer',
        fontFamily: 'inherit', fontSize: 10,
      }}
    >
      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
        <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19M1 1l22 22" />
      </svg>
      {count} hidden
    </button>
  );
}
