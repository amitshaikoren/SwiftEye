/**
 * useAnimationInteraction.js — canvas interaction hook for AnimationPane.
 *
 * Owns: click/hover hit-testing, right-click context menu, node dragging,
 * keyboard shortcuts, and popover-dismiss side effects.
 *
 * Shared refs (canvasRef, positionsRef, transformRef, zoomRef) are
 * declared in the coordinator and passed in.
 */

import { useCallback, useEffect, useRef } from 'react';
import * as d3 from 'd3';
import { NODE_RADIUS } from './animationUtils';

export function useAnimationInteraction({
  canvasRef,
  positionsRef,
  transformRef,
  zoomRef,
  optionsRef,
  // state
  hiddenNodes,
  frameState,
  visibleEdges,
  contextMenu,
  showOptions,
  // setters
  setShowOptions,
  setContextMenu,
  setHovered,
  // callbacks
  onSelectNode,
  onSelectSession,
  togglePlay,
  stepForward,
  stepBackward,
  goToStart,
  goToEnd,
  stopAnimation,
}) {
  // ── Click / hover hit-testing ─────────────────────────────────────
  const handleCanvasEvent = useCallback((e) => {
    setShowOptions(false);
    setContextMenu(null);
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const t = transformRef.current;
    const mx = (e.clientX - rect.left - t.x) / t.k;
    const my = (e.clientY - rect.top - t.y) / t.k;
    const pos = positionsRef.current;

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

      let cpx = (sp.x + dp.x) / 2, cpy = (sp.y + dp.y) / 2;
      if (edge.pairTotal > 1) {
        const edx = dp.x - sp.x, edy = dp.y - sp.y;
        const nx = -edy, ny = edx;
        const len = Math.sqrt(nx * nx + ny * ny) || 1;
        const offset = (edge.pairIndex - (edge.pairTotal - 1) / 2) * 24;
        cpx += (nx / len) * offset;
        cpy += (ny / len) * offset;
      }

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
      if (onSelectNode) onSelectNode(null);
    }
  }, [frameState, visibleEdges, hiddenNodes, onSelectNode, onSelectSession]); // eslint-disable-line react-hooks/exhaustive-deps

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
  }, [hiddenNodes]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Node dragging ────────────────────────────────────────────────
  const dragRef = useRef(null);

  const handleDragStart = useCallback((e) => {
    if (e.button !== 0) return;
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
        dragRef.current = { ip, offsetX: mx - p.x, offsetY: my - p.y };
        e.stopPropagation();
        canvas.setPointerCapture(e.pointerId);
        if (zoomRef.current) d3.select(canvas).on('.zoom', null);
        return;
      }
    }
  }, [hiddenNodes]); // eslint-disable-line react-hooks/exhaustive-deps

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
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleDragEnd = useCallback((e) => {
    if (!dragRef.current) return;
    const canvas = canvasRef.current;
    dragRef.current = null;
    if (canvas) {
      canvas.releasePointerCapture(e.pointerId);
      if (zoomRef.current) d3.select(canvas).call(zoomRef.current);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

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
        default:
          break;
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [togglePlay, stepForward, stepBackward, goToStart, goToEnd, stopAnimation, contextMenu]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Close context menu on outside click / scroll ──────────────────
  useEffect(() => {
    if (!contextMenu) return;
    const close = () => setContextMenu(null);
    document.addEventListener('mousedown', close);
    document.addEventListener('scroll', close, true);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('scroll', close, true);
    };
  }, [contextMenu]); // eslint-disable-line react-hooks/exhaustive-deps

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
  }, [showOptions]); // eslint-disable-line react-hooks/exhaustive-deps

  return { handleCanvasEvent, handleContextMenu, handleDragStart, handleDragMove, handleDragEnd };
}
