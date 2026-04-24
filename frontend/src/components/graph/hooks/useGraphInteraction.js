import { useRef, useEffect } from 'react';
import * as d3 from 'd3';
import { inPolygon } from '../utils/graphColorUtils';

export default function useGraphInteraction({
  cRef, simRef, nRef, eRef, tRef, gRRef, renRef, rafRef, hRef,
  selNRef, pathfindSourceRef, onPathfindTargetRef,
  onSelRef, qhRef, onClearQHRef,
  setCtxMenu, setLasso, setTransformVersion,
  ringGuidesRef,
}) {
  const lassoRef = useRef(null);

  useEffect(() => {
    const c = cRef.current;
    if (!c) return;

    let dn = null;       // node being dragged
    let didDrag = false;
    let zoomEnabled = true;

    const gR = gRRef.current;

    function gN(mx, my) {
      const t = tRef.current;
      const x = (mx - t.x) / t.k;
      const y = (my - t.y) / t.k;
      for (let i = nRef.current.length - 1; i >= 0; i--) {
        const n = nRef.current[i];
        if (Math.hypot(n.x - x, n.y - y) < gR(n) + 5) return n;
      }
      return null;
    }

    function gE(mx, my) {
      const t = tRef.current;
      const x = (mx - t.x) / t.k;
      const y = (my - t.y) / t.k;
      for (const e of eRef.current) {
        const s = typeof e.source === 'object' ? e.source : nRef.current.find(n => n.id === e.source);
        const tg = typeof e.target === 'object' ? e.target : nRef.current.find(n => n.id === e.target);
        if (!s || !tg) continue;
        const dx = tg.x - s.x, dy = tg.y - s.y;
        const l2 = dx * dx + dy * dy;
        if (l2 === 0) continue;
        let t2 = ((x - s.x) * dx + (y - s.y) * dy) / l2;
        t2 = Math.max(0, Math.min(1, t2));
        if (Math.hypot(x - (s.x + t2 * dx), y - (s.y + t2 * dy)) < 8) return e;
      }
      return null;
    }

    // D3 zoom
    const zoom = d3.zoom()
      .scaleExtent([0.08, 10])
      .filter(() => zoomEnabled)
      .on('zoom', e => {
        tRef.current = e.transform;
        if (renRef.current) {
          cancelAnimationFrame(rafRef.current);
          rafRef.current = requestAnimationFrame(renRef.current);
        }
        setTransformVersion(v => v + 1);
      });

    d3.select(c).call(zoom);

    // Hover
    function onMouseMove(e) {
      if (dn) return;
      const r = c.getBoundingClientRect();
      const prev = hRef.current;
      hRef.current = gN(e.clientX - r.left, e.clientY - r.top)?.id || null;
      c.style.cursor = hRef.current ? 'grab' : 'default';
      if (prev !== hRef.current && renRef.current) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = requestAnimationFrame(renRef.current);
      }
    }

    // Drag start
    function onPointerDown(e) {
      if (e.button === 2 && e.shiftKey) {
        e.preventDefault();
        const r = c.getBoundingClientRect();
        const x = e.clientX - r.left, y = e.clientY - r.top;
        lassoRef.current = { points: [{ x, y }] };
        setLasso({ points: [{ x, y }] });
        c.setPointerCapture(e.pointerId);
        return;
      }
      if (e.button !== 0) return;
      const r = c.getBoundingClientRect();
      const n = gN(e.clientX - r.left, e.clientY - r.top);
      if (n) {
        dn = n;
        didDrag = false;
        zoomEnabled = false;
        c.setPointerCapture(e.pointerId);
        c.style.cursor = 'grabbing';
        e.preventDefault();
        e.stopPropagation();
      }
    }

    // Drag move
    function onPointerMove(e) {
      if (lassoRef.current) {
        const r = c.getBoundingClientRect();
        const x = e.clientX - r.left, y = e.clientY - r.top;
        lassoRef.current.points.push({ x, y });
        if (lassoRef.current.points.length % 3 === 0) {
          setLasso({ points: [...lassoRef.current.points] });
        }
        return;
      }
      if (!dn) return;
      didDrag = true;
      const r = c.getBoundingClientRect();
      const t = tRef.current;
      dn.fx = (e.clientX - r.left - t.x) / t.k;
      dn.fy = (e.clientY - r.top - t.y) / t.k;
      if (simRef.current) simRef.current.alpha(0.05).restart();
    }

    // Drag end
    function onPointerUp(e) {
      if (lassoRef.current) {
        const pts = lassoRef.current.points;
        if (pts.length >= 3) {
          const t = tRef.current;
          const selected = nRef.current
            .filter(n => {
              if (n.x == null || n.y == null) return false;
              const sx = n.x * t.k + t.x;
              const sy = n.y * t.k + t.y;
              return inPolygon(sx, sy, pts);
            })
            .map(n => n.id);
          if (selected.length > 0) {
            selected.forEach((id, i) => onSelRef.current('node', id, i > 0));
          }
        }
        lassoRef.current = null;
        setLasso(null);
        c.releasePointerCapture(e.pointerId);
        return;
      }
      if (dn) {
        c.releasePointerCapture(e.pointerId);
        dn = null;
        zoomEnabled = true;
        c.style.cursor = 'default';
        if (didDrag) {
          didDrag = false;
          return;
        }
      }
    }

    // Click
    function onClick(e) {
      if (didDrag) { didDrag = false; return; }
      const r = c.getBoundingClientRect();
      const mx = e.clientX - r.left, my = e.clientY - r.top;
      const n = gN(mx, my);
      if (pathfindSourceRef.current && n) {
        onPathfindTargetRef.current?.(n.id);
        return;
      }
      if (n) { onSelRef.current('node', n.id, e.shiftKey); return; }
      const ed = gE(mx, my);
      if (ed) { onSelRef.current('edge', ed, false); return; }
      // Ring guide click: select all nodes in the component (±10px tolerance in world space)
      const guides = ringGuidesRef?.current ?? [];
      if (guides.length) {
        const t = tRef.current;
        const wx = (mx - t.x) / t.k;
        const wy = (my - t.y) / t.k;
        const hitTol = 10 / t.k;
        const hit = guides.find(g => Math.abs(Math.hypot(wx - g.cx, wy - g.cy) - g.r) < hitTol);
        if (hit) {
          hit.nodeIds.forEach((id, i) => onSelRef.current('node', id, i > 0));
          return;
        }
      }
      onSelRef.current('clear', null, false);
      if (qhRef.current) onClearQHRef.current?.();
    }

    // Double click to unpin
    function onDblClick(e) {
      const r = c.getBoundingClientRect();
      const n = gN(e.clientX - r.left, e.clientY - r.top);
      if (n) {
        n.fx = null;
        n.fy = null;
        if (simRef.current) simRef.current.alpha(0.08).restart();
      }
    }

    // Right-click context menu
    function onContextMenu(e) {
      e.preventDefault();
      if (lassoRef.current) return;
      const r = c.getBoundingClientRect();
      const cx = e.clientX - r.left;
      const cy = e.clientY - r.top;
      const n = gN(cx, cy);
      if (n) {
        const label = n.metadata?.name || (n.hostnames?.length ? n.hostnames[0] : n.id);
        setCtxMenu({ x: cx, y: cy, nodeId: n.id, nodeLabel: label, isSynthetic: !!n.synthetic, isCluster: !!n.is_cluster, isSubnet: !!n.is_subnet, clusterId: n.cluster_id, canvasX: null, canvasY: null, edgeId: null });
      } else {
        const ed = gE(cx, cy);
        if (ed) {
          setCtxMenu({ x: cx, y: cy, nodeId: null, nodeLabel: null, edgeId: ed.id, isSyntheticEdge: !!ed.synthetic, canvasX: null, canvasY: null });
        } else {
          const t = tRef.current;
          const gx = (cx - t.x) / t.k;
          const gy = (cy - t.y) / t.k;
          setCtxMenu({ x: cx, y: cy, nodeId: null, nodeLabel: null, edgeId: null, canvasX: gx, canvasY: gy });
        }
      }
    }

    c.addEventListener('mousemove', onMouseMove);
    c.addEventListener('pointerdown', onPointerDown);
    c.addEventListener('pointermove', onPointerMove);
    c.addEventListener('pointerup', onPointerUp);
    c.addEventListener('click', onClick);
    c.addEventListener('dblclick', onDblClick);
    c.addEventListener('contextmenu', onContextMenu);

    return () => {
      c.removeEventListener('mousemove', onMouseMove);
      c.removeEventListener('pointerdown', onPointerDown);
      c.removeEventListener('pointermove', onPointerMove);
      c.removeEventListener('pointerup', onPointerUp);
      c.removeEventListener('click', onClick);
      c.removeEventListener('dblclick', onDblClick);
      c.removeEventListener('contextmenu', onContextMenu);
    };
  }, []);

}
