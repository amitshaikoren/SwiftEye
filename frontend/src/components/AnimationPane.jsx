/**
 * AnimationPane — temporal animation of node sessions on canvas.
 *
 * Replaces GraphCanvas when animActive === true.
 * Sub-components: header, canvas, controls bar, legend, frame overlay.
 */

import React, { useRef, useEffect, useCallback, useState, useMemo } from 'react';
import * as d3 from 'd3';
import { fB, fN, fTtime } from '../utils';
import { useFilterContext } from '../FilterContext';

// ── Constants ────────────────────────────────────────────────────────────────

const FLASH_DURATION_MS = 900;
const GRID_SIZE = 60;
const NODE_RADIUS = 12;
const SPOTLIGHT_RING_R = 18;

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatAnimTime(ts) {
  if (!ts) return '--:--:--.---';
  const d = new Date(ts * 1000);
  const h = String(d.getHours()).padStart(2, '0');
  const m = String(d.getMinutes()).padStart(2, '0');
  const s = String(d.getSeconds()).padStart(2, '0');
  const ms = String(d.getMilliseconds()).padStart(3, '0');
  return `${h}:${m}:${s}.${ms}`;
}

/** Build a session map from events for quick lookup. */
function buildSessionMap(events) {
  const map = {};
  for (const ev of events) {
    if (ev.type === 'start') {
      map[ev.session_id] = ev;
    }
  }
  return map;
}

/** Compute node positions: spotlight inherit from mainGraph, neighbours via D3 collision. */
function computePositions(animNodeMeta, mainNodes, canvasW, canvasH) {
  const positions = {};
  const mainMap = {};
  for (const n of (mainNodes || [])) {
    if (n.x != null && n.y != null) mainMap[n.id] = { x: n.x, y: n.y };
  }

  // Place all animation nodes
  const allIps = Object.keys(animNodeMeta);
  const spotlightIps = allIps.filter(ip => animNodeMeta[ip]?.is_spotlight);
  const neighbourIps = allIps.filter(ip => !animNodeMeta[ip]?.is_spotlight);

  // Spotlight nodes: inherit main graph positions
  for (const ip of spotlightIps) {
    if (mainMap[ip]) {
      positions[ip] = { x: mainMap[ip].x, y: mainMap[ip].y };
    } else {
      // Fallback: place in center area
      const angle = (spotlightIps.indexOf(ip) / spotlightIps.length) * Math.PI * 2;
      const r = Math.min(canvasW, canvasH) * 0.15;
      positions[ip] = {
        x: canvasW / 2 + Math.cos(angle) * r,
        y: canvasH / 2 + Math.sin(angle) * r,
      };
    }
  }

  // Neighbour nodes: inherit main graph positions, then D3 collision resolve
  const simNodes = [];
  for (const ip of neighbourIps) {
    if (mainMap[ip]) {
      simNodes.push({ id: ip, x: mainMap[ip].x, y: mainMap[ip].y, fx: null, fy: null });
    } else {
      // Random placement near center
      simNodes.push({
        id: ip,
        x: canvasW / 2 + (Math.random() - 0.5) * canvasW * 0.5,
        y: canvasH / 2 + (Math.random() - 0.5) * canvasH * 0.5,
        fx: null, fy: null,
      });
    }
  }

  // Add spotlight as fixed obstacles
  const fixedNodes = spotlightIps.map(ip => ({
    id: ip, ...positions[ip], fx: positions[ip].x, fy: positions[ip].y,
  }));

  if (simNodes.length > 0) {
    const allSimNodes = [...fixedNodes, ...simNodes];
    const sim = d3.forceSimulation(allSimNodes)
      .force('collision', d3.forceCollide().radius(NODE_RADIUS * 2.5))
      .force('charge', d3.forceManyBody().strength(-30))
      .stop();

    // Run a brief tick to resolve overlaps
    for (let i = 0; i < 50; i++) sim.tick();

    for (const n of allSimNodes) {
      if (!positions[n.id]) {
        positions[n.id] = { x: n.x, y: n.y };
      }
    }
  }

  return positions;
}

/** Build edge list from events for rendering. */
function buildEdgeList(sessionMap) {
  const edges = [];
  const pairCount = {}; // track multi-edges between same pair
  for (const [sid, ev] of Object.entries(sessionMap)) {
    const pairKey = [ev.src, ev.dst].sort().join('|');
    pairCount[pairKey] = (pairCount[pairKey] || 0) + 1;
    edges.push({
      session_id: sid,
      src: ev.src,
      dst: ev.dst,
      protocol: ev.protocol,
      bytes: ev.bytes,
      packets: ev.packets,
      pairKey,
      pairIndex: pairCount[pairKey] - 1,
    });
  }
  // Set pairTotal for curvature
  for (const e of edges) {
    e.pairTotal = pairCount[e.pairKey];
  }
  return edges;
}

// ── Main Component ───────────────────────────────────────────────────────────

export default function AnimationPane({
  // Animation state (from useCapture → useAnimationMode)
  animNodes, animEvents, animNodeMeta, animFrame, animPlaying, animSpeed,
  animOpts, frameState, currentEvent, animTimeRange, totalFrames, isIsolated,
  // Actions
  togglePlay, goToFrame, stepForward, stepBackward, goToStart, goToEnd,
  setAnimSpeed, setAnimOpts, stopAnimation, setIsIsolated,
  // External data for positioning
  mainNodes, pColors,
  // Click handlers for detail panels
  onSelectNode, onSelectSession,
}) {
  const canvasRef = useRef(null);
  const wrapRef = useRef(null);
  const [showHistory, setShowHistory] = useState(false);
  const [showOptions, setShowOptions] = useState(false);
  const optionsRef = useRef(null);
  const [hovered, setHovered] = useState(null); // { type: 'node'|'edge', id, x, y }
  const [focusedNode, setFocusedNode] = useState(null); // null = show all, IP string = filter to that spotlight
  const [hiddenNodes, setHiddenNodes] = useState(new Set()); // IPs hidden by user
  const [contextMenu, setContextMenu] = useState(null); // { x, y, ip }
  const [dragState, setDragState] = useState(null); // { ip, startX, startY } for node dragging
  const flashRef = useRef({}); // session_id → timestamp of flash start
  const positionsRef = useRef({});
  const transformRef = useRef({ x: 0, y: 0, k: 1 });
  const zoomRef = useRef(null);
  const historyListRef = useRef(null);

  // Build derived data
  const sessionMap = useMemo(() => buildSessionMap(animEvents), [animEvents]);
  const edgeList = useMemo(() => buildEdgeList(sessionMap), [sessionMap]);
  const filterCtx = useFilterContext();

  // Filtered edges: apply protocol filter + focusedNode + hiddenNodes.
  // Note: when isIsolated is on, the event list itself is already filtered upstream
  // in useAnimationMode, so edgeList only contains spotlight↔spotlight sessions here.
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

  // Filtered events for history panel
  const visibleEvents = useMemo(() => {
    if (!focusedNode && hiddenNodes.size === 0) return animEvents;
    const visibleSids = new Set(visibleEdges.map(e => e.session_id));
    return animEvents.filter(ev => visibleSids.has(ev.session_id));
  }, [animEvents, visibleEdges, focusedNode, hiddenNodes]);

  // ── Compute positions once when animation starts ──────────────────
  useEffect(() => {
    const wrap = wrapRef.current;
    if (!wrap || Object.keys(animNodeMeta).length === 0) return;
    const w = wrap.clientWidth || 800;
    const h = wrap.clientHeight || 600;
    positionsRef.current = computePositions(animNodeMeta, mainNodes, w, h);
  }, [animNodeMeta, mainNodes]);

  // ── Flash tracking ────────────────────────────────────────────────
  useEffect(() => {
    if (!currentEvent || currentEvent.type !== 'start') return;
    flashRef.current[currentEvent.session_id] = performance.now();
  }, [currentEvent]);

  // ── Auto-scroll history panel ─────────────────────────────────────
  useEffect(() => {
    if (!showHistory || !historyListRef.current) return;
    const el = historyListRef.current;
    const current = el.querySelector('.anim-hist-current');
    if (current) current.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }, [animFrame, showHistory]);

  // ── Canvas zoom ───────────────────────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const zoom = d3.zoom()
      .scaleExtent([0.1, 8])
      .on('zoom', (ev) => {
        transformRef.current = ev.transform;
      });
    zoomRef.current = zoom;
    d3.select(canvas).call(zoom);
    return () => { d3.select(canvas).on('.zoom', null); };
  }, []);

  // ── Fit view when positions change ────────────────────────────────
  useEffect(() => {
    const pos = positionsRef.current;
    const canvas = canvasRef.current;
    if (!canvas || !zoomRef.current || Object.keys(pos).length === 0) return;

    const xs = Object.values(pos).map(p => p.x);
    const ys = Object.values(pos).map(p => p.y);
    const minX = Math.min(...xs), maxX = Math.max(...xs);
    const minY = Math.min(...ys), maxY = Math.max(...ys);
    const w = canvas.parentElement.clientWidth || 800;
    const h = canvas.parentElement.clientHeight || 600;
    const padFrac = 0.15;
    const bw = (maxX - minX) || 200;
    const bh = (maxY - minY) || 200;
    const k = Math.min((w * (1 - padFrac * 2)) / bw, (h * (1 - padFrac * 2)) / bh, 2);
    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;

    const transform = d3.zoomIdentity.translate(w / 2 - cx * k, h / 2 - cy * k).scale(k);
    d3.select(canvas).call(zoomRef.current.transform, transform);
    transformRef.current = transform;
  }, [animNodeMeta]);

  // ── Canvas render loop ────────────────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    let rafId;

    function draw() {
      rafId = requestAnimationFrame(draw);
      const parent = canvas.parentElement;
      if (!parent) return;

      const dpr = window.devicePixelRatio || 1;
      const width = parent.clientWidth;
      const height = parent.clientHeight;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = width + 'px';
      canvas.style.height = height + 'px';

      const ctx = canvas.getContext('2d');
      ctx.scale(dpr, dpr);

      const t = transformRef.current;
      const pos = positionsRef.current;
      const { active, ended } = frameState;
      const now = performance.now();
      const pc = pColors || {};
      const opts = animOpts;
      const spotSet = new Set(animNodes);

      // Background
      ctx.fillStyle = '#08090d';
      ctx.fillRect(0, 0, width, height);

      // Vignette
      const vig = ctx.createRadialGradient(width / 2, height / 2, 0, width / 2, height / 2, Math.max(width, height) * 0.7);
      vig.addColorStop(0, 'rgba(0,0,0,0)');
      vig.addColorStop(1, 'rgba(0,0,0,0.10)');
      ctx.fillStyle = vig;
      ctx.fillRect(0, 0, width, height);

      ctx.save();
      ctx.translate(t.x, t.y);
      ctx.scale(t.k, t.k);

      // Grid
      if (t.k > 0.3) {
        const sx = -t.x / t.k, sy = -t.y / t.k;
        const ex = sx + width / t.k, ey = sy + height / t.k;
        ctx.strokeStyle = 'rgba(128,128,128,0.04)';
        ctx.lineWidth = 1 / t.k;
        for (let x = Math.floor(sx / GRID_SIZE) * GRID_SIZE; x < ex; x += GRID_SIZE) {
          ctx.beginPath(); ctx.moveTo(x, sy); ctx.lineTo(x, ey); ctx.stroke();
        }
        for (let y = Math.floor(sy / GRID_SIZE) * GRID_SIZE; y < ey; y += GRID_SIZE) {
          ctx.beginPath(); ctx.moveTo(sx, y); ctx.lineTo(ex, y); ctx.stroke();
        }
      }

      // ── Edges ──────────────────────────────────────────────────────
      for (const edge of visibleEdges) {
        const srcPos = pos[edge.src];
        const dstPos = pos[edge.dst];
        if (!srcPos || !dstPos) continue;

        const isActive = active.has(edge.session_id);
        const isEnded = ended.has(edge.session_id);
        if (!isActive && !isEnded) continue;
        if (isEnded && opts.endedMode === 'disappear') continue;

        // Multi-edge curvature
        let cpx = (srcPos.x + dstPos.x) / 2;
        let cpy = (srcPos.y + dstPos.y) / 2;
        if (edge.pairTotal > 1) {
          const dx = dstPos.x - srcPos.x;
          const dy = dstPos.y - srcPos.y;
          const nx = -dy, ny = dx;
          const len = Math.sqrt(nx * nx + ny * ny) || 1;
          const offset = (edge.pairIndex - (edge.pairTotal - 1) / 2) * 24;
          cpx += (nx / len) * offset;
          cpy += (ny / len) * offset;
        }

        const protoColor = pc[edge.protocol] || '#64748b';

        if (isActive) {
          // Flash glow
          const flashStart = flashRef.current[edge.session_id];
          if (flashStart && (now - flashStart) < FLASH_DURATION_MS) {
            const flashAlpha = 1 - (now - flashStart) / FLASH_DURATION_MS;
            ctx.save();
            ctx.globalAlpha = flashAlpha * 0.4;
            ctx.strokeStyle = protoColor;
            ctx.lineWidth = 12;
            ctx.beginPath();
            ctx.moveTo(srcPos.x, srcPos.y);
            if (edge.pairTotal > 1) {
              ctx.quadraticCurveTo(cpx, cpy, dstPos.x, dstPos.y);
            } else {
              ctx.lineTo(dstPos.x, dstPos.y);
            }
            ctx.stroke();
            ctx.restore();
          }

          // Active edge
          ctx.globalAlpha = 0.9;
          ctx.strokeStyle = protoColor;
          ctx.lineWidth = Math.max(1.5, Math.min(6, Math.log(edge.bytes + 1) * 0.4));
          ctx.setLineDash([]);
        } else {
          // Ended edge
          if (opts.endedMode === 'color') {
            ctx.strokeStyle = opts.endedColor;
            ctx.globalAlpha = 0.5;
          } else {
            ctx.strokeStyle = '#555';
            ctx.globalAlpha = 0.2;
          }
          ctx.lineWidth = 1;
          ctx.setLineDash([5, 4]);
        }

        ctx.beginPath();
        ctx.moveTo(srcPos.x, srcPos.y);
        if (edge.pairTotal > 1) {
          ctx.quadraticCurveTo(cpx, cpy, dstPos.x, dstPos.y);
        } else {
          ctx.lineTo(dstPos.x, dstPos.y);
        }
        ctx.stroke();
        ctx.setLineDash([]);

        // Arrowhead for active edges
        if (isActive) {
          const aLen = 8;
          let ax, ay, angle;
          if (edge.pairTotal > 1) {
            ax = dstPos.x; ay = dstPos.y;
            angle = Math.atan2(dstPos.y - cpy, dstPos.x - cpx);
          } else {
            ax = dstPos.x; ay = dstPos.y;
            angle = Math.atan2(dstPos.y - srcPos.y, dstPos.x - srcPos.x);
          }
          // Pull back arrow to node edge
          const pullback = NODE_RADIUS + 2;
          ax -= Math.cos(angle) * pullback;
          ay -= Math.sin(angle) * pullback;
          ctx.fillStyle = protoColor;
          ctx.beginPath();
          ctx.moveTo(ax, ay);
          ctx.lineTo(ax - aLen * Math.cos(angle - 0.4), ay - aLen * Math.sin(angle - 0.4));
          ctx.lineTo(ax - aLen * Math.cos(angle + 0.4), ay - aLen * Math.sin(angle + 0.4));
          ctx.closePath();
          ctx.fill();
        }

        // Edge label
        if (isActive && opts.edgeLabels !== 'off' && t.k > 0.5) {
          const lx = cpx, ly = cpy - 8;
          ctx.font = `500 ${Math.max(8, 9 / t.k)}px JetBrains Mono, monospace`;
          ctx.textAlign = 'center';
          ctx.textBaseline = 'bottom';
          ctx.fillStyle = protoColor;
          ctx.globalAlpha = 0.8;
          const label = opts.edgeLabels === 'bytes' ? fB(edge.bytes) : edge.protocol;
          ctx.fillText(label, lx, ly);
        }

        ctx.globalAlpha = 1;
      }

      // ── Nodes ──────────────────────────────────────────────────────
      const allIps = Object.keys(pos);
      for (const ip of allIps) {
        const p = pos[ip];
        if (!p) continue;
        if (hiddenNodes.has(ip)) continue;
        const meta = animNodeMeta[ip] || {};
        const isSpotlight = meta.is_spotlight;
        const isPrivate = meta.is_private;

        // Check if this node has any active session
        let hasActive = false;
        for (const edge of visibleEdges) {
          if ((edge.src === ip || edge.dst === ip) && active.has(edge.session_id)) {
            hasActive = true;
            break;
          }
        }

        // Alpha based on state
        if (isSpotlight) {
          ctx.globalAlpha = 1;
        } else if (hasActive) {
          ctx.globalAlpha = 0.75;
        } else {
          if (!opts.showInactive) continue;
          ctx.globalAlpha = 0.28;
        }

        // Fill / stroke colors
        const fillColor = isPrivate ? '#264060' : '#3d2855';
        const strokeColor = isSpotlight ? '#58a6ff' : (isPrivate ? '#5a9ad5' : '#9060cc');

        // Spotlight glow
        if (isSpotlight) {
          const gl = ctx.createRadialGradient(p.x, p.y, NODE_RADIUS, p.x, p.y, NODE_RADIUS * 3);
          gl.addColorStop(0, '#58a6ff44');
          gl.addColorStop(1, 'transparent');
          ctx.fillStyle = gl;
          ctx.fillRect(p.x - NODE_RADIUS * 3, p.y - NODE_RADIUS * 3, NODE_RADIUS * 6, NODE_RADIUS * 6);
        }

        // Node circle
        ctx.beginPath();
        ctx.arc(p.x, p.y, NODE_RADIUS, 0, Math.PI * 2);
        ctx.fillStyle = fillColor;
        ctx.fill();
        ctx.strokeStyle = strokeColor;
        ctx.lineWidth = isSpotlight ? 2.5 : 1.5;
        ctx.stroke();

        // Spotlight selection ring
        if (isSpotlight) {
          ctx.beginPath();
          ctx.arc(p.x, p.y, SPOTLIGHT_RING_R, 0, Math.PI * 2);
          ctx.strokeStyle = '#58a6ff';
          ctx.lineWidth = 2;
          ctx.setLineDash([4, 3]);
          ctx.stroke();
          ctx.setLineDash([]);
        }

        // Label
        if (t.k > 0.4) {
          const fs = Math.max(8, 10 / t.k);
          ctx.font = `500 ${fs}px JetBrains Mono, monospace`;
          ctx.textAlign = 'center';
          ctx.textBaseline = 'top';
          ctx.fillStyle = '#a0aab5';
          ctx.shadowColor = 'rgba(0,0,0,0.8)';
          ctx.shadowOffsetX = 0;
          ctx.shadowOffsetY = 1;
          ctx.shadowBlur = 3;
          const label = meta.hostname || ip;
          ctx.fillText(label, p.x, p.y + NODE_RADIUS + 4);
          ctx.shadowColor = 'transparent';
          ctx.shadowBlur = 0;
          ctx.shadowOffsetX = 0;
          ctx.shadowOffsetY = 0;
        }

        ctx.globalAlpha = 1;
      }

      ctx.restore();
    }

    draw();
    return () => cancelAnimationFrame(rafId);
  }, [frameState, animNodes, animNodeMeta, animOpts, pColors, visibleEdges, animEvents, hiddenNodes]);

  // ── Canvas click/hover ────────────────────────────────────────────
  const handleCanvasEvent = useCallback((e) => {
    // Close popovers when interacting with canvas
    setShowOptions(false);
    setContextMenu(null);
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const t = transformRef.current;
    const mx = (e.clientX - rect.left - t.x) / t.k;
    const my = (e.clientY - rect.top - t.y) / t.k;
    const pos = positionsRef.current;

    // Hit radius scales inversely with zoom so it feels consistent at any zoom level
    const hitR = Math.max(NODE_RADIUS, NODE_RADIUS * 1.5 / t.k);
    const edgeHitR = Math.max(8, 10 / t.k);

    // Check nodes
    for (const ip of Object.keys(pos)) {
      if (hiddenNodes.has(ip)) continue;
      const p = pos[ip];
      const dx = mx - p.x, dy = my - p.y;
      if (dx * dx + dy * dy < hitR * hitR) {
        if (e.type === 'click' && onSelectNode) {
          onSelectNode(ip);
        } else if (e.type === 'mousemove') {
          setHovered({ type: 'node', id: ip, x: e.clientX, y: e.clientY });
          canvas.style.cursor = 'pointer';
        }
        return;
      }
    }

    // Check edges — sample points along curve for hit detection
    const { active, ended } = frameState;
    for (const edge of visibleEdges) {
      if (!active.has(edge.session_id) && !ended.has(edge.session_id)) continue;
      const sp = pos[edge.src], dp = pos[edge.dst];
      if (!sp || !dp) continue;

      // Compute control point (same logic as render)
      let cpx = (sp.x + dp.x) / 2, cpy = (sp.y + dp.y) / 2;
      if (edge.pairTotal > 1) {
        const edx = dp.x - sp.x, edy = dp.y - sp.y;
        const nx = -edy, ny = edx;
        const len = Math.sqrt(nx * nx + ny * ny) || 1;
        const offset = (edge.pairIndex - (edge.pairTotal - 1) / 2) * 24;
        cpx += (nx / len) * offset;
        cpy += (ny / len) * offset;
      }

      // Sample 20 points along the quadratic bezier and check distance
      let minDist = Infinity;
      const steps = 20;
      for (let si = 0; si <= steps; si++) {
        const st = si / steps;
        const inv = 1 - st;
        const px = inv * inv * sp.x + 2 * inv * st * cpx + st * st * dp.x;
        const py = inv * inv * sp.y + 2 * inv * st * cpy + st * st * dp.y;
        const d = Math.sqrt((mx - px) ** 2 + (my - py) ** 2);
        if (d < minDist) minDist = d;
      }

      if (minDist < edgeHitR) {
        if (e.type === 'click' && onSelectSession) {
          onSelectSession(edge.session_id);
        } else if (e.type === 'mousemove') {
          setHovered({ type: 'edge', id: edge.session_id, x: e.clientX, y: e.clientY });
          canvas.style.cursor = 'pointer';
        }
        return;
      }
    }

    if (e.type === 'mousemove') {
      setHovered(null);
      canvas.style.cursor = 'default';
    }
    if (e.type === 'click') {
      // Click on empty canvas — close detail
      if (onSelectNode) onSelectNode(null);
    }
  }, [frameState, visibleEdges, hiddenNodes, onSelectNode, onSelectSession]);

  // ── Right-click context menu ──────────────────────────────────────
  const handleContextMenu = useCallback((e) => {
    e.preventDefault();
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const t = transformRef.current;
    const mx = (e.clientX - rect.left - t.x) / t.k;
    const my = (e.clientY - rect.top - t.y) / t.k;
    const pos = positionsRef.current;
    const hitR = Math.max(NODE_RADIUS, NODE_RADIUS * 1.5 / t.k);

    for (const ip of Object.keys(pos)) {
      if (hiddenNodes.has(ip)) continue;
      const p = pos[ip];
      const dx = mx - p.x, dy = my - p.y;
      if (dx * dx + dy * dy < hitR * hitR) {
        setContextMenu({ x: e.clientX, y: e.clientY, ip });
        return;
      }
    }
    setContextMenu(null);
  }, [hiddenNodes]);

  // ── Node dragging ────────────────────────────────────────────────
  const dragRef = useRef(null); // { ip, offsetX, offsetY }

  const handleDragStart = useCallback((e) => {
    if (e.button !== 0) return; // left click only
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const t = transformRef.current;
    const mx = (e.clientX - rect.left - t.x) / t.k;
    const my = (e.clientY - rect.top - t.y) / t.k;
    const pos = positionsRef.current;
    const hitR = Math.max(NODE_RADIUS, NODE_RADIUS * 1.5 / t.k);

    for (const ip of Object.keys(pos)) {
      if (hiddenNodes.has(ip)) continue;
      const p = pos[ip];
      const dx = mx - p.x, dy = my - p.y;
      if (dx * dx + dy * dy < hitR * hitR) {
        // Found a node — start dragging, suppress D3 zoom
        dragRef.current = { ip, offsetX: mx - p.x, offsetY: my - p.y };
        e.stopPropagation();
        canvas.setPointerCapture(e.pointerId);
        // Temporarily disable D3 zoom during drag
        if (zoomRef.current) d3.select(canvas).on('.zoom', null);
        return;
      }
    }
  }, [hiddenNodes]);

  const handleDragMove = useCallback((e) => {
    if (!dragRef.current) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const t = transformRef.current;
    const mx = (e.clientX - rect.left - t.x) / t.k;
    const my = (e.clientY - rect.top - t.y) / t.k;
    const { ip, offsetX, offsetY } = dragRef.current;
    positionsRef.current = {
      ...positionsRef.current,
      [ip]: { x: mx - offsetX, y: my - offsetY },
    };
  }, []);

  const handleDragEnd = useCallback((e) => {
    if (!dragRef.current) return;
    const canvas = canvasRef.current;
    dragRef.current = null;
    if (canvas) {
      canvas.releasePointerCapture(e.pointerId);
      // Re-enable D3 zoom
      if (zoomRef.current) d3.select(canvas).call(zoomRef.current);
    }
  }, []);

  // ── Keyboard shortcuts ────────────────────────────────────────────
  useEffect(() => {
    function onKey(e) {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
      switch (e.key) {
        case ' ':
          e.preventDefault();
          togglePlay();
          break;
        case 'ArrowRight':
          e.preventDefault();
          stepForward();
          break;
        case 'ArrowLeft':
          e.preventDefault();
          stepBackward();
          break;
        case 'Home':
          e.preventDefault();
          goToStart();
          break;
        case 'End':
          e.preventDefault();
          goToEnd();
          break;
        case 'Escape':
          if (contextMenu) { setContextMenu(null); break; }
          stopAnimation();
          break;
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [togglePlay, stepForward, stepBackward, goToStart, goToEnd, stopAnimation, contextMenu]);

  // ── Close context menu on outside click / scroll ──────────────────
  useEffect(() => {
    if (!contextMenu) return;
    const close = () => setContextMenu(null);
    document.addEventListener('mousedown', close);
    document.addEventListener('scroll', close, true);
    return () => { document.removeEventListener('mousedown', close); document.removeEventListener('scroll', close, true); };
  }, [contextMenu]);

  // ── Close options popover on outside click ────────────────────────
  useEffect(() => {
    if (!showOptions) return;
    function onClick(e) {
      if (optionsRef.current && !optionsRef.current.contains(e.target)) {
        setShowOptions(false);
      }
    }
    document.addEventListener('mousedown', onClick);
    return () => document.removeEventListener('mousedown', onClick);
  }, [showOptions]);

  // ── Scrubber interaction ──────────────────────────────────────────
  const handleScrubberClick = useCallback((e) => {
    const bar = e.currentTarget;
    const rect = bar.getBoundingClientRect();
    const frac = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
    const frame = Math.round(frac * totalFrames);
    goToFrame(frame);
  }, [totalFrames, goToFrame]);

  // ── Computed display values ───────────────────────────────────────
  const currentTime = currentEvent ? formatAnimTime(currentEvent.time) : formatAnimTime(animTimeRange.min);
  const progressPct = totalFrames > 0 ? (animFrame / totalFrames) * 100 : 0;
  const watchLabel = useMemo(() => {
    if (animNodes.length <= 3) return animNodes.join(', ');
    return animNodes.slice(0, 3).join(', ') + ` [+${animNodes.length - 3} more]`;
  }, [animNodes]);

  const neighbourCount = useMemo(() => {
    return Object.keys(animNodeMeta).filter(ip => !animNodeMeta[ip]?.is_spotlight).length;
  }, [animNodeMeta]);

  // Event description for current frame
  const eventDesc = useMemo(() => {
    if (!currentEvent) return { text: 'Ready', detail: '', cls: 'init' };
    const arrow = currentEvent.type === 'start' ? '──▶' : '──×';
    const text = `${currentEvent.src} ─[${currentEvent.protocol}]${arrow} ${currentEvent.dst}`;
    const detail = currentEvent.type === 'start' ? 'new session' : 'session ended';
    return { text, detail, cls: currentEvent.type };
  }, [currentEvent]);

  // Speed options
  const speeds = [0.5, 1, 2, 5];

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
            {/* Protocol colors from active edges */}
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

          {/* Context Menu */}
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

        {/* History Panel */}
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
            <div style={{ fontSize: 9, color: 'var(--txDD)' }}>{visibleEvents.length}{visibleEvents.length !== totalFrames ? `/${totalFrames}` : ''} events</div>
          </div>
          <div ref={historyListRef} style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden', padding: '4px 0' }}>
            {visibleEvents.map((ev, i) => {
              // Find the global frame index for this event
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
      </div>

      {/* ── Controls Bar ───────────────────────────────────────────── */}
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
              View session
            </button>
          )}
        </div>
      </div>

      {/* Pulse keyframe animation */}
      <style>{`
        @keyframes animPulse { 0%,100%{opacity:1} 50%{opacity:0.2} }
      `}</style>
    </div>
  );
}

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
