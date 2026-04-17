/**
 * useAnimationCanvas.js — canvas rendering hook for AnimationPane.
 *
 * Owns: position computation, zoom setup, fit-view, flash tracking,
 * and the RAF-driven canvas render loop.
 *
 * All shared refs (canvasRef, wrapRef, positionsRef, transformRef,
 * zoomRef, flashRef) are declared in the coordinator and passed in so
 * sibling hooks can read them without coupling.
 */

import { useEffect } from 'react';
import * as d3 from 'd3';
import {
  computePositions,
  FLASH_DURATION_MS,
  GRID_SIZE,
  NODE_RADIUS,
  SPOTLIGHT_RING_R,
} from './animationUtils';
import { fB } from '../utils';

export function useAnimationCanvas({
  canvasRef,
  wrapRef,
  positionsRef,
  transformRef,
  zoomRef,
  flashRef,
  // data
  animNodeMeta,
  mainNodes,
  currentEvent,
  animNodes,
  animOpts,
  pColors,
  visibleEdges,
  frameState,
  hiddenNodes,
  animEvents,
  // persisted positions (survives panel switches)
  savedPositionsRef,
}) {
  // ── Compute positions when animation starts ───────────────────────
  useEffect(() => {
    const wrap = wrapRef.current;
    if (!wrap || Object.keys(animNodeMeta).length === 0) return;
    const w = wrap.clientWidth || 800;
    const h = wrap.clientHeight || 600;
    const fresh = computePositions(animNodeMeta, mainNodes, w, h);
    // Restore any positions the user dragged before a panel switch
    const saved = savedPositionsRef?.current || {};
    positionsRef.current = { ...fresh, ...saved };
  }, [animNodeMeta, mainNodes]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Flash tracking ────────────────────────────────────────────────
  useEffect(() => {
    if (!currentEvent || currentEvent.type !== 'start') return;
    flashRef.current[currentEvent.session_id] = performance.now();
  }, [currentEvent]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Canvas zoom setup ─────────────────────────────────────────────
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
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Fit view when positions change ───────────────────────────────
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
  }, [animNodeMeta]); // eslint-disable-line react-hooks/exhaustive-deps

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
  }, [frameState, animNodes, animNodeMeta, animOpts, pColors, visibleEdges, animEvents, hiddenNodes]); // eslint-disable-line react-hooks/exhaustive-deps
}
