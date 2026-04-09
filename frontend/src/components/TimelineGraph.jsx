/**
 * TimelineGraph — researcher's narrative canvas (v0.21.0).
 *
 * Pure SVG + d3-force with LOW repulsion (the user-requested setting):
 * placed events get gentle collision + light charge so they don't overlap,
 * but the user owns positioning via drag.
 *
 * Behaviors:
 *   - Drag an Event card from the right panel onto the canvas → place it
 *     at the drop position. Drag a placed node to reposition it.
 *   - "Draw edge" mode (toolbar button) → click two nodes to create a
 *     manual TimelineEdge. The user can label it; default color is white.
 *   - Suggested edges (computed from useEvents) appear dashed/dimmed
 *     between any two PLACED events that share a connection reason.
 *     Click → accept/reject popover. Accept = converts to a manual edge.
 *   - Ruler mode → reflows placed events top-to-bottom by capture_time.
 *     X stays manual, Y is mapped to a vertical time axis. Events with
 *     null capture_time cluster at the bottom.
 *   - Click a placed node → side detail card. Click a manual edge →
 *     edit its label/color/annotation. Right-click → unplace / remove.
 */
import React, { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import * as d3 from 'd3';
import { SEVERITY_COLOR, REASON_META } from '../hooks/useEvents';

// ── Constants ──────────────────────────────────────────────────────────────

const NODE_R = 22;          // visual radius of a placed event node
const COLLIDE_R = 34;       // collision radius (slightly larger than visual)
const CHARGE = -40;         // light repulsion (the "low force push")
const ALPHA_DECAY = 0.04;   // simulation cools quickly
const MANUAL_EDGE_COLOR = '#c9d1d9';

// ── Helpers ────────────────────────────────────────────────────────────────

function entityIcon(entity_type) {
  if (entity_type === 'edge')    return '↔';
  if (entity_type === 'session') return '◫';
  return '◉';
}

function shortLabel(text, max = 18) {
  if (!text) return '';
  return text.length > max ? text.slice(0, max - 1) + '…' : text;
}

// ── Main component ─────────────────────────────────────────────────────────

export default function TimelineGraph({
  events = [],
  timelineEdges = [],
  suggestedEdges = [],
  addTimelineEdge,
  removeTimelineEdge,
  acceptSuggestion,
  placeEvent,
  unplaceEvent,
  onSelectEntity,
}) {
  const svgRef    = useRef(null);
  const wrapRef   = useRef(null);
  const simRef    = useRef(null);
  // Persistent zoom/pan transform. Updated by d3.zoom; read by render.
  // Kept in a ref (not state) so the d3-zoom drag loop doesn't fight React.
  const tRef      = useRef(d3.zoomIdentity);
  // Local mirror of placed events with live x/y. Source of truth for the
  // simulation; React state used for re-renders.
  const nodesRef  = useRef([]);
  const [tick, setTick] = useState(0);
  const [zoomTick, setZoomTick] = useState(0);
  const [size, setSize] = useState({ w: 800, h: 600 });

  // UI state
  const [rulerOn, setRulerOn] = useState(false);
  const [drawMode, setDrawMode] = useState(false);
  const [drawSrc, setDrawSrc]   = useState(null); // event id picked first
  const [selectedNode, setSelectedNode] = useState(null);  // event id
  const [selectedEdge, setSelectedEdge] = useState(null);  // timeline edge id
  const [suggestionPopup, setSuggestionPopup] = useState(null);  // { suggestion, x, y }
  const [edgeLabelPrompt, setEdgeLabelPrompt] = useState(null); // { from, to } awaiting label
  const [ctxMenu, setCtxMenu] = useState(null); // { x, y, eventId }
  const [hoveredEdgeId, setHoveredEdgeId] = useState(null);

  // ── Resize observer ──────────────────────────────────────────────────────

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(es => {
      for (const e of es) setSize({ w: e.contentRect.width, h: e.contentRect.height });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // ── Placed events list (the only events on the canvas) ──────────────────

  const placedEvents = useMemo(
    () => events.filter(e => e.canvas_x != null && e.canvas_y != null),
    [events]
  );

  // ── Time-axis range (for ruler mode) ─────────────────────────────────────

  const timeRange = useMemo(() => {
    const ts = placedEvents.map(e => e.capture_time).filter(t => t != null);
    if (ts.length === 0) return null;
    const min = Math.min(...ts);
    const max = Math.max(...ts);
    return min === max ? { min, max: max + 1 } : { min, max };
  }, [placedEvents]);

  function timeToY(t) {
    if (!timeRange || t == null) return size.h - 60;
    const margin = 60;
    const usable = Math.max(40, size.h - margin * 2);
    return margin + ((t - timeRange.min) / (timeRange.max - timeRange.min)) * usable;
  }

  // ── d3-force simulation: created once, fed by nodesRef ──────────────────

  useEffect(() => {
    const sim = d3.forceSimulation()
      .force('charge', d3.forceManyBody().strength(CHARGE))
      .force('collision', d3.forceCollide().radius(COLLIDE_R))
      .alphaDecay(ALPHA_DECAY)
      .alphaMin(0.01)
      .on('tick', () => {
        // Mirror node positions back into the React-rendered ref. Do NOT
        // call placeEvent on every tick — that would thrash parent state.
        // We only persist on drag-end / unmount.
        setTick(t => t + 1);
      });
    simRef.current = sim;
    return () => { sim.stop(); };
  }, []);

  // ── Sync simulation nodes when placedEvents changes ─────────────────────
  //
  // Strategy:
  //   - Reuse sim nodes whose event id still exists (preserve x/y/vx/vy).
  //   - Add new nodes at their stored canvas_x/canvas_y from the event.
  //   - Drop sim nodes whose event was removed/unplaced.
  //   - Apply ruler-mode y pull / release as a force.

  useEffect(() => {
    const sim = simRef.current;
    if (!sim) return;
    const prevById = new Map(nodesRef.current.map(n => [n.id, n]));
    const next = placedEvents.map(ev => {
      const prev = prevById.get(ev.id);
      if (prev) {
        // Update event reference but preserve simulation x/y/vx/vy
        prev.event = ev;
        return prev;
      }
      return {
        id: ev.id,
        event: ev,
        x: ev.canvas_x,
        y: ev.canvas_y,
        vx: 0, vy: 0,
      };
    });
    nodesRef.current = next;
    sim.nodes(next);

    // Ruler-mode y force (pull each node toward its time-mapped y).
    if (rulerOn) {
      sim.force('y-time', d3.forceY(d => timeToY(d.event?.capture_time)).strength(0.18));
    } else {
      sim.force('y-time', null);
    }
    sim.alpha(0.5).restart();
  }, [placedEvents, rulerOn, size.w, size.h]);

  // ── Zoom + pan ───────────────────────────────────────────────────────────
  //
  // d3.zoom() handles wheel-zoom and click-drag-pan on the SVG background.
  // Pan is suppressed when the gesture starts on a node or edge (those have
  // data-pan-skip and their own pointer handlers).

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const sel = d3.select(svg);
    const zoom = d3.zoom()
      .scaleExtent([0.3, 3])
      .filter((e) => {
        // Always allow wheel zoom; only allow drag-pan from background.
        if (e.type === 'wheel') return true;
        return !e.target.closest('[data-pan-skip]');
      })
      .on('zoom', (e) => {
        tRef.current = e.transform;
        setZoomTick((t) => t + 1);
      });
    sel.call(zoom);
    // Keep d3-zoom's internal state in sync with our ref so programmatic
    // resets (later) work cleanly.
    return () => { sel.on('.zoom', null); };
  }, []);

  // ── Drag handlers (placed nodes) ─────────────────────────────────────────

  const dragRef = useRef(null);  // { id, offsetX, offsetY }

  // Screen-space coordinate (for popup positioning).
  function svgPoint(clientX, clientY) {
    const svg = svgRef.current;
    if (!svg) return { x: 0, y: 0 };
    const rect = svg.getBoundingClientRect();
    return { x: clientX - rect.left, y: clientY - rect.top };
  }

  // Canvas-space coordinate (for node positions / drops). Inverts the
  // current zoom/pan transform so node coordinates remain stable across
  // zoom levels — the simulation, persisted canvas_x/canvas_y, and the
  // ruler all live in untransformed canvas space.
  function canvasPoint(clientX, clientY) {
    const sp = svgPoint(clientX, clientY);
    const [cx, cy] = tRef.current.invert([sp.x, sp.y]);
    return { x: cx, y: cy };
  }

  function onNodePointerDown(e, node) {
    if (drawMode) {
      // In draw mode: clicks pick endpoints
      e.stopPropagation();
      if (!drawSrc) {
        setDrawSrc(node.id);
      } else if (drawSrc !== node.id) {
        setEdgeLabelPrompt({ from: drawSrc, to: node.id });
        setDrawSrc(null);
      }
      return;
    }
    e.stopPropagation();
    e.target.setPointerCapture?.(e.pointerId);
    const pt = canvasPoint(e.clientX, e.clientY);
    dragRef.current = { id: node.id, dx: pt.x - node.x, dy: pt.y - node.y };
    simRef.current?.alphaTarget(0.3).restart();
    node.fx = node.x;
    node.fy = node.y;
  }

  function onNodePointerMove(e) {
    const drag = dragRef.current;
    if (!drag) return;
    const node = nodesRef.current.find(n => n.id === drag.id);
    if (!node) return;
    const pt = canvasPoint(e.clientX, e.clientY);
    node.fx = pt.x - drag.dx;
    node.fy = pt.y - drag.dy;
  }

  function onNodePointerUp(e) {
    const drag = dragRef.current;
    if (!drag) return;
    const node = nodesRef.current.find(n => n.id === drag.id);
    simRef.current?.alphaTarget(0);
    if (node) {
      // Persist final position back to the parent event store
      placeEvent?.(node.id, node.fx ?? node.x, node.fy ?? node.y);
      node.fx = null;
      node.fy = null;
    }
    dragRef.current = null;
  }

  // ── Card drop from EventsPanel ───────────────────────────────────────────

  function onCanvasDragOver(e) {
    if (e.dataTransfer?.types?.includes('application/x-swifteye-event')) {
      e.preventDefault();
      e.dataTransfer.dropEffect = 'copy';
    }
  }

  function onCanvasDrop(e) {
    e.preventDefault();
    const eventId = e.dataTransfer?.getData('application/x-swifteye-event');
    if (!eventId) return;
    const ev = events.find(x => x.id === eventId);
    if (!ev) return;
    const pt = canvasPoint(e.clientX, e.clientY);
    placeEvent?.(eventId, pt.x, pt.y);
  }

  // ── Suggested edges visible on canvas ────────────────────────────────────
  //
  // A SuggestedEdge is rendered iff BOTH endpoints are currently placed AND
  // there is no manual edge already covering this pair (manual takes
  // precedence — once accepted, the suggestion is satisfied).

  const visibleSuggested = useMemo(() => {
    const placedSet = new Set(placedEvents.map(e => e.id));
    const manualKeys = new Set(timelineEdges.map(te =>
      [te.from_event_id, te.to_event_id].sort().join('|')
    ));
    return suggestedEdges.filter(s => {
      if (!placedSet.has(s.from_event_id) || !placedSet.has(s.to_event_id)) return false;
      const k = [s.from_event_id, s.to_event_id].sort().join('|');
      if (manualKeys.has(k)) return false;
      return true;
    });
  }, [suggestedEdges, placedEvents, timelineEdges]);

  // ── Coordinate lookup for an event id ────────────────────────────────────

  function eventXY(eventId) {
    const n = nodesRef.current.find(x => x.id === eventId);
    if (!n) return null;
    return { x: n.fx ?? n.x, y: n.fy ?? n.y };
  }

  // ── Click handlers ───────────────────────────────────────────────────────

  function onCanvasClick() {
    setSelectedNode(null);
    setSelectedEdge(null);
    setSuggestionPopup(null);
    setCtxMenu(null);
  }

  function onSuggestedClick(e, suggestion) {
    e.stopPropagation();
    const pt = svgPoint(e.clientX, e.clientY);
    setSuggestionPopup({ suggestion, x: pt.x, y: pt.y });
  }

  function onManualEdgeClick(e, edge) {
    e.stopPropagation();
    setSelectedEdge(edge.id);
    setSelectedNode(null);
  }

  function onNodeClick(e, node) {
    if (drawMode) return;
    e.stopPropagation();
    setSelectedNode(node.id);
    setSelectedEdge(null);
  }

  function onNodeContextMenu(e, node) {
    e.preventDefault();
    e.stopPropagation();
    const pt = svgPoint(e.clientX, e.clientY);
    setCtxMenu({ x: pt.x, y: pt.y, eventId: node.id });
  }

  // ── Edge label prompt: confirm a manual edge ─────────────────────────────

  function confirmEdgeLabel(label) {
    if (!edgeLabelPrompt) return;
    addTimelineEdge?.(edgeLabelPrompt.from, edgeLabelPrompt.to, {
      type: 'manual',
      label: label || null,
      color: MANUAL_EDGE_COLOR,
    });
    setEdgeLabelPrompt(null);
  }

  // ── Suggestion accept/reject ─────────────────────────────────────────────

  function acceptSuggestionReason(suggestion, reason) {
    acceptSuggestion?.(suggestion.from_event_id, suggestion.to_event_id, reason);
    setSuggestionPopup(null);
  }

  // ── Selected entities for the side panel ─────────────────────────────────

  const selectedNodeObj = selectedNode ? events.find(e => e.id === selectedNode) : null;
  const selectedEdgeObj = selectedEdge ? timelineEdges.find(te => te.id === selectedEdge) : null;

  // ── Render ───────────────────────────────────────────────────────────────

  return (
    <div ref={wrapRef} style={{
      flex: 1, display: 'flex', flexDirection: 'column',
      background: 'var(--bg)', minHeight: 0, position: 'relative',
    }}>
      {/* Sub-toolbar for the timeline canvas */}
      <div style={{
        padding: '6px 12px', borderBottom: '1px solid var(--bd)',
        background: 'var(--bgP)', display: 'flex', alignItems: 'center', gap: 6,
        flexShrink: 0,
      }}>
        <button className={'btn' + (drawMode ? ' on' : '')}
          onClick={() => { setDrawMode(d => !d); setDrawSrc(null); }}
          style={{ fontSize: 9, padding: '2px 10px' }}>
          {drawMode ? 'Exit draw mode' : '✏ Draw edge'}
        </button>
        {drawMode && drawSrc && (
          <span style={{ fontSize: 9, color: 'var(--ac)' }}>Click another node to connect…</span>
        )}
        <div style={{ width: 1, height: 16, background: 'var(--bd)' }} />
        <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9, color: 'var(--txM)', cursor: 'pointer' }}>
          <input type="checkbox" checked={rulerOn} onChange={e => setRulerOn(e.target.checked)} />
          Ruler (time)
        </label>
        <div style={{ flex: 1 }} />
        <span style={{ fontSize: 9, color: 'var(--txD)' }}>
          {placedEvents.length} placed · {timelineEdges.length} manual · {visibleSuggested.length} suggested
        </span>
      </div>

      {/* Empty hint when nothing placed yet */}
      {placedEvents.length === 0 && (
        <div style={{
          position: 'absolute', top: '50%', left: '50%',
          transform: 'translate(-50%, -50%)',
          fontSize: 11, color: 'var(--txD)', textAlign: 'center',
          pointerEvents: 'none', maxWidth: 320, lineHeight: 1.6,
        }}>
          Drag flagged events from the right panel onto this canvas to begin building your narrative.
        </div>
      )}

      {/* SVG canvas */}
      <svg
        ref={svgRef}
        width={size.w} height={Math.max(120, size.h - 36)}
        style={{ flex: 1, cursor: drawMode ? 'crosshair' : 'default', userSelect: 'none' }}
        onDragOver={onCanvasDragOver}
        onDrop={onCanvasDrop}
        onClick={onCanvasClick}
        onPointerMove={onNodePointerMove}
        onPointerUp={onNodePointerUp}
      >
        {/* Transparent background rect — gives d3.zoom a target so pan
            works over empty canvas. Without it, pointerdowns on empty
            space hit the <svg> root only when there are no children. */}
        <rect x={0} y={0} width={size.w} height={Math.max(120, size.h - 36)} fill="transparent" />

        {/* All zoom/pan-affected content lives inside this group. The
            ruler is included so its ticks scale with the canvas. */}
        <g transform={tRef.current.toString()}>
        {/* Ruler axis (only when ruler mode is on) */}
        {rulerOn && timeRange && (
          <g pointerEvents="none">
            <line x1={20} y1={timeToY(timeRange.min)} x2={20} y2={timeToY(timeRange.max)}
              stroke="var(--bd)" strokeWidth={1} />
            <text x={28} y={timeToY(timeRange.min) + 4} fill="var(--txD)" fontSize={9}>
              {new Date(timeRange.min * 1000).toLocaleTimeString()}
            </text>
            <text x={28} y={timeToY(timeRange.max) + 4} fill="var(--txD)" fontSize={9}>
              {new Date(timeRange.max * 1000).toLocaleTimeString()}
            </text>
          </g>
        )}

        {/* Suggested edges (rendered first so manual edges paint on top) */}
        {visibleSuggested.map((s, i) => {
          const a = eventXY(s.from_event_id);
          const b = eventXY(s.to_event_id);
          if (!a || !b) return null;
          const id = `${s.from_event_id}|${s.to_event_id}`;
          const isHovered = hoveredEdgeId === id;
          return (
            <g key={'sugg:' + id} data-pan-skip="true" style={{ cursor: 'pointer' }}
              onMouseEnter={() => setHoveredEdgeId(id)}
              onMouseLeave={() => setHoveredEdgeId(null)}
              onClick={e => onSuggestedClick(e, s)}>
              <line x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                stroke={s.primary_color} strokeWidth={isHovered ? 2.5 : 1.5}
                strokeDasharray="6 4" opacity={isHovered ? 0.95 : 0.55} />
              {/* Reason count badge for merged-multi-reason suggestions */}
              {s.reasons.length > 1 && (() => {
                const mx = (a.x + b.x) / 2;
                const my = (a.y + b.y) / 2;
                return (
                  <g>
                    <circle cx={mx} cy={my} r={9} fill="var(--bgP)" stroke={s.primary_color} strokeWidth={1.5} />
                    <text x={mx} y={my + 3} fill={s.primary_color} fontSize={9}
                      textAnchor="middle" fontWeight={700}>
                      ×{s.reasons.length}
                    </text>
                  </g>
                );
              })()}
            </g>
          );
        })}

        {/* Manual / accepted edges */}
        {timelineEdges.map(te => {
          const a = eventXY(te.from_event_id);
          const b = eventXY(te.to_event_id);
          if (!a || !b) return null;
          const isSelected = selectedEdge === te.id;
          return (
            <g key={'te:' + te.id} data-pan-skip="true" style={{ cursor: 'pointer' }}
              onClick={e => onManualEdgeClick(e, te)}>
              <line x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                stroke={te.color || MANUAL_EDGE_COLOR}
                strokeWidth={isSelected ? 3 : 2}
                opacity={isSelected ? 1 : 0.85} />
              {te.label && (() => {
                const mx = (a.x + b.x) / 2;
                const my = (a.y + b.y) / 2 - 6;
                return (
                  <text x={mx} y={my} fill={te.color || MANUAL_EDGE_COLOR} fontSize={10}
                    textAnchor="middle" style={{ pointerEvents: 'none' }}>
                    {shortLabel(te.label, 24)}
                  </text>
                );
              })()}
            </g>
          );
        })}

        {/* Placed event nodes */}
        {nodesRef.current.map(n => {
          const ev = n.event;
          if (!ev) return null;
          const sevColor = SEVERITY_COLOR[ev.severity] || '#8b949e';
          const isSelected = selectedNode === ev.id;
          const isDrawSrc = drawSrc === ev.id;
          const cx = n.fx ?? n.x;
          const cy = n.fy ?? n.y;
          if (cx == null || cy == null) return null;
          return (
            <g key={'n:' + ev.id} data-pan-skip="true"
              style={{ cursor: drawMode ? 'crosshair' : 'grab' }}
              onPointerDown={e => onNodePointerDown(e, n)}
              onClick={e => onNodeClick(e, n)}
              onContextMenu={e => onNodeContextMenu(e, n)}>
              {/* Severity ring */}
              <circle cx={cx} cy={cy} r={NODE_R}
                fill="var(--bgP)" stroke={sevColor}
                strokeWidth={isSelected || isDrawSrc ? 3 : 2}
                opacity={1} />
              {/* Entity icon */}
              <text x={cx} y={cy + 5} textAnchor="middle"
                fontSize={18} fill={sevColor}
                style={{ pointerEvents: 'none' }}>
                {entityIcon(ev.entity_type)}
              </text>
              {/* Title below */}
              <text x={cx} y={cy + NODE_R + 12} textAnchor="middle"
                fontSize={10} fill="var(--tx)" fontWeight={600}
                style={{ pointerEvents: 'none' }}>
                {shortLabel(ev.title, 22)}
              </text>
              {/* Entity id, smaller, dim */}
              <text x={cx} y={cy + NODE_R + 24} textAnchor="middle"
                fontSize={9} fill="var(--txD)"
                style={{ pointerEvents: 'none' }}>
                {shortLabel(ev.node_id || ev.edge_id || (ev.session_id || '').slice(0, 8), 24)}
              </text>
            </g>
          );
        })}
        </g>
      </svg>

      {/* Node context menu */}
      {ctxMenu && (
        <>
          <div onClick={() => setCtxMenu(null)} style={{ position: 'absolute', inset: 0, zIndex: 198 }} />
          <div style={{
            position: 'absolute', left: ctxMenu.x, top: ctxMenu.y, zIndex: 199,
            background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 4,
            boxShadow: '0 4px 12px rgba(0,0,0,.4)',
            display: 'flex', flexDirection: 'column', minWidth: 140,
          }}>
            <button className="btn" style={{ fontSize: 10, padding: '5px 10px', textAlign: 'left', borderRadius: 0, border: 'none' }}
              onClick={() => {
                const ev = events.find(e => e.id === ctxMenu.eventId);
                if (ev) {
                  if (ev.entity_type === 'node') onSelectEntity?.('node', ev.node_id);
                  if (ev.entity_type === 'edge') onSelectEntity?.('edge', ev.edge_id);
                  if (ev.entity_type === 'session') onSelectEntity?.('session', ev.session_id);
                }
                setCtxMenu(null);
              }}>View in graph</button>
            <button className="btn" style={{ fontSize: 10, padding: '5px 10px', textAlign: 'left', borderRadius: 0, border: 'none' }}
              onClick={() => { unplaceEvent?.(ctxMenu.eventId); setCtxMenu(null); }}>Unplace</button>
          </div>
        </>
      )}

      {/* Suggestion accept/reject popup */}
      {suggestionPopup && (
        <>
          <div onClick={() => setSuggestionPopup(null)} style={{ position: 'absolute', inset: 0, zIndex: 198 }} />
          <div style={{
            position: 'absolute', left: suggestionPopup.x, top: suggestionPopup.y, zIndex: 199,
            background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 6,
            boxShadow: '0 4px 14px rgba(0,0,0,.5)',
            padding: 8, minWidth: 220, maxWidth: 280,
          }}>
            <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 6, fontWeight: 600 }}>
              SUGGESTED CONNECTION
            </div>
            {suggestionPopup.suggestion.reasons.map((r, i) => (
              <div key={i} style={{
                display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4,
                padding: '4px 6px', background: 'var(--bg)', borderRadius: 4,
              }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: r.color, flexShrink: 0 }} />
                <span style={{ fontSize: 11, color: 'var(--tx)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {r.label}
                </span>
                <button className="btn"
                  onClick={() => acceptSuggestionReason(suggestionPopup.suggestion, r)}
                  style={{ fontSize: 9, padding: '1px 8px' }}>Accept</button>
              </div>
            ))}
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 4 }}>
              <button className="btn" onClick={() => setSuggestionPopup(null)}
                style={{ fontSize: 9, padding: '2px 10px' }}>Reject all</button>
            </div>
          </div>
        </>
      )}

      {/* Edge label prompt (after picking two nodes in draw mode) */}
      {edgeLabelPrompt && (
        <>
          <div onClick={() => setEdgeLabelPrompt(null)} style={{ position: 'absolute', inset: 0, zIndex: 198, background: 'rgba(0,0,0,.4)' }} />
          <div style={{
            position: 'absolute', left: '50%', top: '40%', transform: 'translate(-50%, -50%)',
            zIndex: 199,
            background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 6,
            boxShadow: '0 8px 24px rgba(0,0,0,.6)',
            padding: 14, minWidth: 280,
          }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--tx)', marginBottom: 8 }}>Label this connection</div>
            <input
              autoFocus
              placeholder="e.g. C2 beacon"
              onKeyDown={e => {
                if (e.key === 'Enter') confirmEdgeLabel(e.target.value.trim());
                if (e.key === 'Escape') setEdgeLabelPrompt(null);
              }}
              style={{
                width: '100%', background: 'var(--bg)', border: '1px solid var(--bd)',
                borderRadius: 4, padding: '6px 8px', fontSize: 11,
                color: 'var(--tx)', fontFamily: 'var(--fn)', outline: 'none',
              }}
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 8, gap: 6 }}>
              <button className="btn" onClick={() => setEdgeLabelPrompt(null)} style={{ fontSize: 10, padding: '3px 10px' }}>Cancel</button>
              <button className="btn on" onClick={() => confirmEdgeLabel('')} style={{ fontSize: 10, padding: '3px 10px' }}>Skip label</button>
            </div>
          </div>
        </>
      )}

      {/* Selected node detail card */}
      {selectedNodeObj && (
        <div style={{
          position: 'absolute', right: 12, bottom: 12, zIndex: 50,
          background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 6,
          padding: 12, width: 240, maxWidth: '40%',
          boxShadow: '0 6px 18px rgba(0,0,0,.4)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
            <span style={{
              width: 8, height: 8, borderRadius: '50%',
              background: SEVERITY_COLOR[selectedNodeObj.severity] || '#8b949e',
            }} />
            <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--tx)', flex: 1 }}>{selectedNodeObj.title}</div>
            <button className="btn" onClick={() => setSelectedNode(null)} style={{ fontSize: 9, padding: '0 6px' }}>✕</button>
          </div>
          <div style={{ fontSize: 10, color: 'var(--txD)', fontFamily: 'var(--fn)', marginBottom: 6 }}>
            {selectedNodeObj.entity_type} · {selectedNodeObj.node_id || selectedNodeObj.edge_id || (selectedNodeObj.session_id || '').slice(0, 8)}
          </div>
          {selectedNodeObj.description && (
            <div style={{ fontSize: 11, color: 'var(--txM)', lineHeight: 1.5, marginBottom: 8 }}>
              {selectedNodeObj.description}
            </div>
          )}
          {selectedNodeObj.capture_time && (
            <div style={{ fontSize: 9, color: 'var(--txD)', marginBottom: 8 }}>
              {new Date(selectedNodeObj.capture_time * 1000).toLocaleString()}
            </div>
          )}
          <div style={{ display: 'flex', gap: 4 }}>
            <button className="btn" style={{ fontSize: 9, padding: '3px 8px' }}
              onClick={() => {
                if (selectedNodeObj.entity_type === 'node') onSelectEntity?.('node', selectedNodeObj.node_id);
                if (selectedNodeObj.entity_type === 'edge') onSelectEntity?.('edge', selectedNodeObj.edge_id);
                if (selectedNodeObj.entity_type === 'session') onSelectEntity?.('session', selectedNodeObj.session_id);
              }}>View in graph</button>
            <button className="btn" style={{ fontSize: 9, padding: '3px 8px' }}
              onClick={() => unplaceEvent?.(selectedNodeObj.id)}>Unplace</button>
          </div>
        </div>
      )}

      {/* Selected manual edge detail */}
      {selectedEdgeObj && (
        <div style={{
          position: 'absolute', right: 12, bottom: 12, zIndex: 50,
          background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 6,
          padding: 12, width: 240, maxWidth: '40%',
          boxShadow: '0 6px 18px rgba(0,0,0,.4)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--tx)', flex: 1 }}>
              {selectedEdgeObj.label || 'Connection'}
            </div>
            <button className="btn" onClick={() => setSelectedEdge(null)} style={{ fontSize: 9, padding: '0 6px' }}>✕</button>
          </div>
          <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 6 }}>
            {selectedEdgeObj.type === 'manual' ? 'Manual edge' : 'Accepted suggestion'}
          </div>
          <textarea
            value={selectedEdgeObj.annotation || ''}
            onChange={e => {
              // We don't have updateTimelineEdge plumbed; settle for label-only edits
              // (annotation field is data-model only in Phase 1).
            }}
            placeholder="Annotation (read-only in Phase 1)"
            rows={3}
            readOnly
            style={{
              width: '100%', background: 'var(--bg)', border: '1px solid var(--bd)',
              borderRadius: 4, padding: '5px 7px', fontSize: 10,
              color: 'var(--txM)', fontFamily: 'var(--fn)', resize: 'vertical', outline: 'none',
            }}
          />
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 6 }}>
            <button className="btn" style={{ fontSize: 9, padding: '3px 10px', color: '#f85149', borderColor: '#f85149' }}
              onClick={() => { removeTimelineEdge?.(selectedEdgeObj.id); setSelectedEdge(null); }}>Remove</button>
          </div>
        </div>
      )}
    </div>
  );
}
