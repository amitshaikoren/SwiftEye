/**
 * GraphCanvas — D3 force-directed network graph on HTML canvas.
 *
 * CRITICAL BUG FIXES applied:
 *   1. Canvas resize: reads parentElement.clientWidth/Height directly in the
 *      render loop every frame, eliminating the black-bar-on-resize issue
 *      caused by ResizeObserver lag.
 *   2. Node dragging: uses pointer events + setPointerCapture + zoom filter
 *      toggling so drag and zoom never conflict.
 */

import React, { useRef, useEffect, useState, useLayoutEffect, useCallback } from 'react';
import { CLUSTER_COLORS } from '../clusterView';
import * as d3 from 'd3';

export default function GraphCanvas({
  nodes, edges, onSelect, onInvestigate, onInvestigateNeighbours, onHideNode, investigationNodes,
  displayFilterNodes, displayFilterEdges,
  selectedNodes, selectedEdge, pColors,
  containerRef, theme,
  annotations = [], onAddAnnotation, onUpdateAnnotation, onDeleteAnnotation,
  onAddNodeAnnotation, onAddEdgeAnnotation,
  onAddSyntheticNode, onAddSyntheticEdge, onDeleteSynthetic, onUnclusterSubnet,
  onExpandCluster, onRelayout, onCreateManualCluster,
  onStartPathfind, pathfindSource, onPathfindTarget, onCancelPathfind,
  labelThreshold = 0,
  graphWeightMode = 'bytes',
  queryHighlight = null,
  onClearQueryHighlight,
}) {
  const cRef = useRef(null);
  const simRef = useRef(null);
  const nRef = useRef([]);
  const eRef = useRef([]);
  const tRef = useRef(d3.zoomIdentity);
  const hRef = useRef(null);
  const selNRef = useRef(new Set());
  const selERef = useRef(null);
  const pcRef = useRef(pColors);
  const onSelRef = useRef(onSelect);
  const onInvRef = useRef(onInvestigate);
  const onInvNbRef = useRef(onInvestigateNeighbours);
  const onClearQHRef = useRef(onClearQueryHighlight);
  useEffect(() => { onClearQHRef.current = onClearQueryHighlight; }, [onClearQueryHighlight]);
  const labelThreshRef = useRef(labelThreshold);
  useEffect(() => { labelThreshRef.current = labelThreshold; }, [labelThreshold]);
  const graphWeightModeRef = useRef(graphWeightMode);
  // Single authoritative node-radius function — reads graphWeightModeRef dynamically.
  // Stored in a ref so both the simulation effect and pointer effect call the same closure.
  const gRRef = useRef(null);
  if (!gRRef.current) {
    gRRef.current = function gR(n) {
      if (n.is_cluster) return Math.max(14, Math.min(36, Math.sqrt(n.member_count) * 6 + 8));
      if (n.synthetic) return Math.max(8, Math.min(28, n.size || 14));
      if (graphWeightModeRef.current === 'bytes') {
        return Math.max(5, Math.min(28, Math.log(Math.max(1, n.total_bytes)) * 2));
      }
      return Math.max(5, Math.min(28, Math.sqrt(n.packet_count) * 2 + 3));
    };
  }
  useEffect(() => {
    graphWeightModeRef.current = graphWeightMode;
    // Update collision radius so physics matches the new visual sizes
    if (simRef.current) {
      const gR = gRRef.current;
      simRef.current
        .force('collision', d3.forceCollide().radius(d => d.is_cluster ? gR(d) * 1.8 + 15 : gR(d) + 10))
        .alpha(0.15).restart();
    }
    if (renRef.current) renRef.current();
  }, [graphWeightMode]);
  const invNodesRef = useRef(investigationNodes);
  const dfNodesRef = useRef(displayFilterNodes);
  const dfEdgesRef = useRef(displayFilterEdges);
  const qhRef = useRef(queryHighlight);
  const renRef = useRef(null);
  const rafRef = useRef(null);
  const [ctxMenu, setCtxMenu] = useState(null); // {x, y, nodeId, nodeLabel, edgeId, isSynthetic, isSyntheticEdge, isCluster, isSubnet, canvasX, canvasY}
  const menuRef = useRef(null);
  const [lasso, setLasso] = useState(null);      // {points:[{x,y}]} — freehand lasso polygon
  const lassoRef = useRef(null);                 // ref mirror for event handlers
  const [transformVersion, setTransformVersion] = useState(0); // bumped on zoom/pan to reposition annotation overlays
  const [showSyntheticNodeForm, setShowSyntheticNodeForm] = useState(false);
  const [showSyntheticEdgeForm, setShowSyntheticEdgeForm] = useState(false);
  const [synEdgeSrc, setSynEdgeSrc] = useState('');
  const [editingAnn, setEditingAnn] = useState(null); // {id} being edited inline
  const annotationsRef = useRef(annotations);
  useEffect(() => { annotationsRef.current = annotations; }, [annotations]);

  // Reposition context menu if it overflows the canvas bottom or right edge
  useLayoutEffect(() => {
    const el = menuRef.current;
    const container = cRef.current?.parentElement;
    if (!el || !container || !ctxMenu) return;
    const cW = container.clientWidth;
    const cH = container.clientHeight;
    const mW = el.offsetWidth;
    const mH = el.offsetHeight;
    let x = ctxMenu.x + 2;
    let y = ctxMenu.y + 2;
    if (x + mW > cW) x = Math.max(0, ctxMenu.x - mW - 2);
    if (y + mH > cH) y = Math.max(0, ctxMenu.y - mH - 2);
    el.style.left = x + 'px';
    el.style.top = y + 'px';
  }, [ctxMenu]);

  // Keep refs in sync with props
  useEffect(() => { selNRef.current = new Set(selectedNodes); }, [selectedNodes]);
  useEffect(() => { selERef.current = selectedEdge; }, [selectedEdge]);
  useEffect(() => { pcRef.current = pColors; }, [pColors]);
  useEffect(() => { onSelRef.current = onSelect; }, [onSelect]);
  useEffect(() => { onInvRef.current = onInvestigate; }, [onInvestigate]);
  useEffect(() => { onInvNbRef.current = onInvestigateNeighbours; }, [onInvestigateNeighbours]);
  const pathfindSourceRef = useRef(pathfindSource);
  const onPathfindTargetRef = useRef(onPathfindTarget);
  useEffect(() => { pathfindSourceRef.current = pathfindSource; }, [pathfindSource]);
  useEffect(() => { onPathfindTargetRef.current = onPathfindTarget; }, [onPathfindTarget]);
  useEffect(() => {
    invNodesRef.current = investigationNodes;
    if (renRef.current) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = requestAnimationFrame(renRef.current);
    }
  }, [investigationNodes]);

  useEffect(() => {
    dfNodesRef.current = displayFilterNodes;
    dfEdgesRef.current = displayFilterEdges;
    if (renRef.current) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = requestAnimationFrame(renRef.current);
    }
  }, [displayFilterNodes, displayFilterEdges]);

  useEffect(() => {
    qhRef.current = queryHighlight;
    if (renRef.current) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = requestAnimationFrame(renRef.current);
    }
  }, [queryHighlight]);

  // Re-render on selection change
  useEffect(() => {
    if (renRef.current) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = requestAnimationFrame(renRef.current);
    }
  }, [selectedNodes, selectedEdge]);

  // Re-render on theme change — CSS vars update instantly but canvas needs a nudge
  useEffect(() => {
    if (!renRef.current) return;
    // Small delay to let the browser apply the new CSS class before we read getComputedStyle
    const t = setTimeout(() => {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = requestAnimationFrame(renRef.current);
    }, 20);
    return () => clearTimeout(t);
  }, [theme]);

  // Re-render when label threshold changes
  useEffect(() => {
    if (!renRef.current) return;
    cancelAnimationFrame(rafRef.current);
    rafRef.current = requestAnimationFrame(renRef.current);
  }, [labelThreshold]);

  // doExportPNG — download the current graph canvas as a PNG
  function doExportPNG() {
    const canvas = cRef.current;
    if (!canvas) return;
    const a = document.createElement('a');
    a.href = canvas.toDataURL('image/png');
    a.download = 'swifteye-graph.png';
    a.click();
  }

  // doRelayout — unpin all nodes and reheat the simulation for a clean redistribution
  function doRelayout() {
    if (!simRef.current) return;
    nRef.current.forEach(n => { delete n.fx; delete n.fy; });
    simRef.current.alpha(0.9).alphaTarget(0).restart();
  }

  // ── Helper: read container size directly (FIX #1) ────────────────
  function getSize() {
    const el = containerRef?.current;
    if (!el) return { width: 800, height: 600 };
    return { width: el.clientWidth, height: el.clientHeight };
  }

  // ── Simulation setup ─────────────────────────────────────────────
  useEffect(() => {
    const { width, height } = getSize();

    if (!nodes.length) {
      const c = cRef.current;
      if (c) {
        const dpr = window.devicePixelRatio || 1;
        c.width = width * dpr;
        c.height = height * dpr;
        c.style.width = width + 'px';
        c.style.height = height + 'px';
        const x = c.getContext('2d');
        x.scale(dpr, dpr);
        x.fillStyle = getComputedStyle(document.body).getPropertyValue('--bg').trim() || '#08090d';
        x.fillRect(0, 0, width, height);
      }
      if (simRef.current) simRef.current.stop();
      nRef.current = [];
      eRef.current = [];
      return;
    }

    // Preserve positions from previous nodes
    const em = new Map();
    for (const n of nRef.current) em.set(n.id, n);

    const nn = nodes.map(n => {
      const e = em.get(n.id);
      return {
        ...n,
        x: e?.x ?? width / 2 + (Math.random() - 0.5) * 300,
        y: e?.y ?? height / 2 + (Math.random() - 0.5) * 300,
        vx: e?.vx ?? 0,
        vy: e?.vy ?? 0,
        fx: e?.fx ?? null,
        fy: e?.fy ?? null,
      };
    });

    const ids = new Set(nn.map(n => n.id));
    const ne = edges
      .filter(e => ids.has(e.source?.id || e.source) && ids.has(e.target?.id || e.target))
      .map(e => ({ ...e, source: e.source?.id || e.source, target: e.target?.id || e.target }));

    nRef.current = nn;
    eRef.current = ne;
    if (simRef.current) simRef.current.stop();

    // Cluster-aware forces: mega-nodes need more room
    const hasAnyClusters = nn.some(n => n.is_cluster);
    const nodeCount = nn.length;
    // For large graphs the repulsion cascades — tighter distanceMax lets links win.
    // Scale: <50 nodes → 500px, 50–200 → 350px, >200 → 200px.
    const chargeDistMax = hasAnyClusters ? 500
      : nodeCount > 200 ? 200
      : nodeCount > 50  ? 350
      : 500;
    const sim = d3.forceSimulation(nn)
      .force('charge', d3.forceManyBody()
        .strength(d => d.is_cluster ? -400 - (d.member_count || 0) * 20 : -280)
        .distanceMax(chargeDistMax))
      .force('link', d3.forceLink(ne).id(d => d.id)
        .distance(d => {
          const s = typeof d.source === 'object' ? d.source : null;
          const t = typeof d.target === 'object' ? d.target : null;
          if (s?.is_cluster || t?.is_cluster) return 220;
          return 160;
        })
        .strength(0.4))
      .force('center', d3.forceCenter(width / 2, height / 2).strength(0.04))
      .force('collision', d3.forceCollide().radius(d =>
        d.is_cluster ? gRRef.current(d) * 1.8 + 15 : gRRef.current(d) + 8))
      .force('x', d3.forceX(width / 2).strength(0.02))
      .force('y', d3.forceY(height / 2).strength(0.02))
      .alphaDecay(0.02)
      .on('tick', render);

    simRef.current = sim;

    const gR = gRRef.current;

    // ── Render function (reads container size each frame — FIX #1) ──
    function render() {
      const c = cRef.current;
      if (!c) return;
      const { width, height } = getSize();
      const ctx = c.getContext('2d');
      const dpr = window.devicePixelRatio || 1;

      c.width = width * dpr;
      c.height = height * dpr;
      c.style.width = width + 'px';
      c.style.height = height + 'px';
      ctx.scale(dpr, dpr);

      // Read CSS variables for theme-aware colors (re-read each frame so theme changes apply instantly)
      const cs = getComputedStyle(document.body);
      const cv = k => cs.getPropertyValue(k).trim();
      const bgColor       = cv('--bg')           || '#08090d';
      const nodePrivate   = cv('--node-private')  || '#264060';
      const nodePrivateS  = cv('--node-private-s')|| '#5a9ad5';
      const nodeExternal  = cv('--node-external') || '#3d2855';
      const nodeExternalS = cv('--node-external-s')|| '#9060cc';
      const nodeSubnet    = cv('--node-subnet')   || '#253545';
      const nodeSubnetS   = cv('--node-subnet-s') || '#557080';
      // Cluster palette imported from clusterView.js (shared with ClusterLegend)
      const nodeGateway   = cv('--node-gateway')  || '#3d3018';
      const nodeGatewayS  = cv('--node-gateway-s')|| '#e0b020';
      const nodeLabel     = cv('--node-label')    || '#a0aab5';
      const acColor       = cv('--ac')            || '#58a6ff';
      const acGColor      = cv('--acG')           || '#3fb950';

      const t = tRef.current;
      const ss = selNRef.current;
      const hs = ss.size > 0;
      const se = selERef.current;
      const pc = pcRef.current;
      const inv = invNodesRef.current; // Set of node IDs in investigation component, or null
      const dfN = dfNodesRef.current;  // Set of node IDs passing display filter, or null
      const dfE = dfEdgesRef.current;  // Set of edge IDs passing display filter, or null

      ctx.fillStyle = bgColor;
      ctx.fillRect(0, 0, width, height);
      // Subtle edge darkening vignette — no center highlight (was visible as
      // a yellowish disc on dark/OLED themes due to white-on-black blending)
      const vig = ctx.createRadialGradient(width/2, height/2, 0, width/2, height/2, Math.max(width, height) * 0.7);
      vig.addColorStop(0, 'rgba(0,0,0,0)');
      vig.addColorStop(1, 'rgba(0,0,0,0.10)');
      ctx.fillStyle = vig;
      ctx.fillRect(0, 0, width, height);
      ctx.save();
      ctx.translate(t.x, t.y);
      ctx.scale(t.k, t.k);

      // Grid
      if (t.k > 0.3) {
        const gs = 60;
        const sx = -t.x / t.k, sy = -t.y / t.k;
        const ex = sx + width / t.k, ey = sy + height / t.k;
        ctx.strokeStyle = 'rgba(128,128,128,0.04)';
        ctx.lineWidth = 1 / t.k;
        for (let x = Math.floor(sx / gs) * gs; x < ex; x += gs) {
          ctx.beginPath(); ctx.moveTo(x, sy); ctx.lineTo(x, ey); ctx.stroke();
        }
        for (let y = Math.floor(sy / gs) * gs; y < ey; y += gs) {
          ctx.beginPath(); ctx.moveTo(sx, y); ctx.lineTo(ex, y); ctx.stroke();
        }
      }

      // Edges
      const wMode = graphWeightModeRef.current;
      const edgeMetric = e => wMode === 'packets' ? (e.packet_count || 0) : (e.total_bytes || 0);
      const meb = Math.max(...eRef.current.map(edgeMetric), 1);
      for (const edge of eRef.current) {
        const src = typeof edge.source === 'object' ? edge.source : nRef.current.find(n => n.id === edge.source);
        const tgt = typeof edge.target === 'object' ? edge.target : nRef.current.find(n => n.id === edge.target);
        if (!src || !tgt) continue;
        const isSel = se?.id === edge.id;
        const w = Math.max(0.6, (edgeMetric(edge) / meb) * 10);
        const col = pc[edge.protocol] || '#64748b';
        const sId = typeof src === 'object' ? src.id : src;
        const tId = typeof tgt === 'object' ? tgt.id : tgt;
        const con = hs && (ss.has(sId) || ss.has(tId));
        const inInv = !inv || (inv.has(sId) && inv.has(tId));
        const inDf  = !dfE || dfE.has(edge.id);

        const edgeColor = edge.synthetic ? (edge.color || '#f0883e') : col;
        // Synthetic edges use a fixed visible width; real edges are traffic-proportional
        const edgeW = edge.synthetic ? 2 : w;

        // Query highlight: check both orderings since edge IDs are "u|v" sorted
        const qh = qhRef.current;
        const eqh = qh?.edges && (qh.edges.has(`${sId}|${tId}`) || qh.edges.has(`${tId}|${sId}`));

        if (!inInv || !inDf) { ctx.globalAlpha = 0.04; }
        else if (edge.synthetic) ctx.globalAlpha = isSel ? 1 : hs ? (con ? 1 : 0.35) : 0.85;
        else ctx.globalAlpha = isSel ? 1 : hs ? (con ? 0.9 : 0.2) : 0.85;

        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);
        ctx.strokeStyle = isSel ? '#fff' : eqh ? '#f0883e' : edgeColor;
        ctx.lineWidth = isSel ? edgeW + 2 : eqh ? edgeW + 1.5 : edgeW;
        if (edge.synthetic) { ctx.setLineDash([6, 4]); } else { ctx.setLineDash([]); }
        ctx.stroke();
        ctx.setLineDash([]);
        if (isSel) {
          ctx.strokeStyle = edgeColor + '55';
          ctx.lineWidth = edgeW + 6;
          ctx.stroke();
        }
        ctx.globalAlpha = 1;
      }

      // Nodes
      for (const node of nRef.current) {
        const r = gR(node);
        const isSel = ss.has(node.id);
        const isH = hRef.current === node.id;
        const inInv = !inv || inv.has(node.id);
        const inDf  = !dfN || dfN.has(node.id);
        const isC = hs && eRef.current.some(e => {
          const s = typeof e.source === 'object' ? e.source.id : e.source;
          const t2 = typeof e.target === 'object' ? e.target.id : e.target;
          return (ss.has(s) && t2 === node.id) || (ss.has(t2) && s === node.id);
        });

        if (!inInv || !inDf) { ctx.globalAlpha = 0.05; }
        else ctx.globalAlpha = hs ? (isSel || isC ? 1 : 0.3) : 1;

        // Glow
        if (isSel || isH) {
          const gl = ctx.createRadialGradient(node.x, node.y, r, node.x, node.y, r * 3);
          gl.addColorStop(0, (isSel ? '#58a6ff' : '#3fb950') + '44');
          gl.addColorStop(1, 'transparent');
          ctx.fillStyle = gl;
          ctx.fillRect(node.x - r * 3, node.y - r * 3, r * 6, r * 6);
        }

        // Shape
        const isGateway = node.plugin_data?.network_role?.role === 'gateway';
        if (node.is_cluster) {
          // Hexagon for cluster mega-nodes
          const cc = CLUSTER_COLORS[(node.cluster_id || 0) % CLUSTER_COLORS.length];
          const hr = r * 1.8;
          ctx.beginPath();
          for (let i = 0; i < 6; i++) {
            const angle = (Math.PI / 3) * i - Math.PI / 6;
            const hx = node.x + hr * Math.cos(angle);
            const hy = node.y + hr * Math.sin(angle);
            if (i === 0) ctx.moveTo(hx, hy); else ctx.lineTo(hx, hy);
          }
          ctx.closePath();
          ctx.fillStyle = isSel ? cc + '44' : cc + '18';
          ctx.fill();
          ctx.strokeStyle = isSel ? '#fff' : isH ? acGColor : cc;
          ctx.lineWidth = isSel || isH ? 2.5 : 2;
          ctx.stroke();
          // Member count badge inside
          if (node.member_count && t.k > 0.3) {
            ctx.font = `bold ${Math.max(9, 11 / t.k)}px JetBrains Mono, monospace`;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = cc;
            ctx.fillText(String(node.member_count), node.x, node.y);
          }
        } else if (node.is_subnet) {
          const s = r * 2.0;
          const rad = 4;
          ctx.beginPath();
          if (ctx.roundRect) {
            ctx.roundRect(node.x - s / 2, node.y - s / 2, s, s, rad);
          } else {
            ctx.rect(node.x - s / 2, node.y - s / 2, s, s);
          }
          ctx.fillStyle = isSel ? acColor + '33' : nodeSubnet;
          ctx.fill();
          ctx.strokeStyle = isSel ? acColor : isH ? acGColor : nodeSubnetS;
          ctx.lineWidth = isSel ? 2.5 : 1.5;
          ctx.setLineDash([4, 2]);
          ctx.stroke();
          ctx.setLineDash([]);
          // Member count badge (number of IPs in the subnet group)
          const memberCount = node.ips?.length || node.member_count;
          if (memberCount && t.k > 0.3) {
            ctx.font = `bold ${Math.max(8, 10 / t.k)}px JetBrains Mono, monospace`;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillStyle = nodeSubnetS;
            ctx.fillText(String(memberCount), node.x, node.y);
          }
        } else if (isGateway) {
          // Diamond shape for gateway/router nodes
          const s = r * 1.6;
          ctx.save();
          ctx.translate(node.x, node.y);
          ctx.rotate(Math.PI / 4);
          ctx.beginPath();
          ctx.rect(-s / 2, -s / 2, s, s);
          ctx.fillStyle = isSel ? acColor + '33' : nodeGateway;
          ctx.fill();
          ctx.strokeStyle = isSel ? acColor : isH ? acGColor : nodeGatewayS;
          ctx.lineWidth = isSel || isH ? 2.5 : 1.8;
          ctx.stroke();
          ctx.restore();
        } else {
          ctx.beginPath();
          ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
          const p = node.is_private;
          if (node.synthetic) {
            // Looks like a regular node but in the chosen colour.
            // Dashed border is kept as a subtle indicator; fill is solid and visible.
            const nc = node.color || '#f0883e';
            ctx.fillStyle = isSel ? nc + '55' : nc + '22';
            ctx.fill();
            ctx.strokeStyle = isSel ? '#fff' : isH ? '#fff' : nc;
            ctx.lineWidth = isSel || isH ? 2.5 : 2;
            ctx.setLineDash([4, 3]);
            ctx.stroke();
            ctx.setLineDash([]);
          } else {
            ctx.fillStyle = isSel ? acColor + '33' : p ? nodePrivate : nodeExternal;
            ctx.fill();
            ctx.strokeStyle = isSel ? acColor : isH ? acGColor : p ? nodePrivateS : nodeExternalS;
            ctx.lineWidth = isSel || isH ? 2.5 : 1.5;
            ctx.stroke();
          }
        }

        // Query highlight ring
        const qh = qhRef.current;
        if (qh && qh.nodes && qh.nodes.has(node.id)) {
          ctx.save();
          ctx.globalAlpha = 0.9;
          ctx.beginPath();
          ctx.arc(node.x, node.y, r + 4, 0, Math.PI * 2);
          ctx.strokeStyle = '#f0883e';
          ctx.lineWidth = 2.5;
          ctx.stroke();
          // Outer glow
          const qgl = ctx.createRadialGradient(node.x, node.y, r, node.x, node.y, r * 2.5);
          qgl.addColorStop(0, 'rgba(240,136,62,0.25)');
          qgl.addColorStop(1, 'transparent');
          ctx.fillStyle = qgl;
          ctx.fillRect(node.x - r * 2.5, node.y - r * 2.5, r * 5, r * 5);
          ctx.restore();
        }

        // Synthetic ✦ marker — small, sits just below the node label
        if (node.synthetic && t.k > 0.25) {
          const nc = node.color || '#f0883e';
          ctx.font = `bold ${Math.max(7, 8 / t.k)}px sans-serif`;
          ctx.textAlign = 'center';
          ctx.textBaseline = 'top';
          ctx.fillStyle = nc + 'dd';
          ctx.fillText('✦', node.x, node.y + r + 15);
        }

        // Label — prefer metadata name > first hostname > node ID
        // Skip if node bytes are below the labelThreshold (unless selected/hovered)
        const thresh = labelThreshRef.current || 0;
        if (t.k > 0.45 && (thresh === 0 || (node.total_bytes || 0) >= thresh || isSel || isH)) {
          const fs = Math.max(8, 10 / t.k);
          ctx.font = `500 ${fs}px JetBrains Mono, monospace`;
          ctx.textAlign = 'center';
          ctx.textBaseline = 'top';
          // Label priority: metadata name > hostname > synthetic label > node ID
          // Synthetic nodes have a user-provided label field that should always be shown
          // instead of the UUID that serves as the node's internal ID.
          const displayName = node.metadata?.name
            || (node.hostnames?.length ? node.hostnames[0] : null)
            || ((node.synthetic || node.is_cluster) && node.label ? node.label : null);
          const rawId = (node.synthetic || node.is_cluster) && node.label ? node.label : node.id;
          const lb = displayName
            ? (displayName.length > 22 ? displayName.slice(0, 20) + '…' : displayName)
            : (rawId.length > 22 ? rawId.slice(0, 20) + '…' : rawId);
          ctx.fillStyle = 'rgba(0,0,0,0.7)';
          ctx.fillText(lb, node.x + 0.5, node.y + r + 5.5);
          ctx.fillStyle = displayName ? '#22d3ee' : isSel ? acColor : isH ? '#e6edf3' : nodeLabel;
          ctx.fillText(lb, node.x, node.y + r + 5);
        }
        ctx.globalAlpha = 1;
      }
      ctx.restore();
    }

    renRef.current = render;
    return () => sim.stop();
  }, [nodes, edges]);

  // ── Re-center simulation when container resizes ──────────────────
  useEffect(() => {
    // Poll for size changes. When the container resizes (e.g. right panel opens,
    // scrollbar appears/disappears, window resizes), update the center force so
    // nodes drift toward the new center on their next natural tick.
    //
    // IMPORTANT: do NOT restart the simulation with any alpha heat here.
    // The previous code used alpha(0.01).restart() which caused nodes to visibly
    // pull away every time a node was clicked (clicking opens the detail panel,
    // which changes the layout slightly, which changes clientWidth by a pixel
    // or two, which triggered the restart). Even alpha=0.01 with alphaDecay=0.02
    // produces visible movement for several frames.
    //
    // Fix: update the center force only. If the sim is still warm (alpha > 0),
    // it will naturally incorporate the new center on its next tick. If it has
    // cooled (alpha ≤ alphaMin), don't restart — just trigger a single re-render
    // so the canvas redraws at the correct size.
    const el = containerRef?.current;
    if (!el) return;
    let prevW = el.clientWidth, prevH = el.clientHeight;

    const interval = setInterval(() => {
      const w = el.clientWidth, h = el.clientHeight;
      if (w !== prevW || h !== prevH) {
        prevW = w;
        prevH = h;
        if (simRef.current) {
          // Update the centering force for the new dimensions
          simRef.current.force('center', d3.forceCenter(w / 2, h / 2).strength(0.04));
          simRef.current.force('x', d3.forceX(w / 2).strength(0.015));
          simRef.current.force('y', d3.forceY(h / 2).strength(0.015));
          // Only restart if the simulation is still warm — let a cooled sim stay still.
          // A cooled sim has alpha <= alphaMin (default 0.001).
          if (simRef.current.alpha() > 0.001) {
            simRef.current.restart();
          } else if (renRef.current) {
            // Sim has cooled — just redraw so the canvas fills the new size
            cancelAnimationFrame(rafRef.current);
            rafRef.current = requestAnimationFrame(renRef.current);
          }
        } else if (renRef.current) {
          cancelAnimationFrame(rafRef.current);
          rafRef.current = requestAnimationFrame(renRef.current);
        }
      }
    }, 200);

    return () => clearInterval(interval);
  }, []);

  // ── Interaction layer (FIX #2: pointer events + zoom coordination) ─
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

    // D3 zoom — respects zoomEnabled flag
    const zoom = d3.zoom()
      .scaleExtent([0.08, 10])
      .filter(() => zoomEnabled)
      .on('zoom', e => {
        tRef.current = e.transform;
        if (renRef.current) {
          cancelAnimationFrame(rafRef.current);
          rafRef.current = requestAnimationFrame(renRef.current);
        }
        // Increment transformVersion to force a React re-render so annotation
        // HTML overlays recalculate their screen positions from the new transform.
        // This is the only way to keep HTML elements in sync with D3 zoom — the
        // canvas redraws via requestAnimationFrame but React components only update
        // when state changes.
        setTransformVersion(v => v + 1);
      });

    d3.select(c).call(zoom);

    // Hover
    function onMouseMove(e) {
      if (dn) return; // skip hover during drag
      const r = c.getBoundingClientRect();
      const prev = hRef.current;
      hRef.current = gN(e.clientX - r.left, e.clientY - r.top)?.id || null;
      c.style.cursor = hRef.current ? 'grab' : 'default';
      if (prev !== hRef.current && renRef.current) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = requestAnimationFrame(renRef.current);
      }
    }

    // Drag start — pointer events for reliable capture
    // Shift+right-button drag = lasso selection
    function onPointerDown(e) {
      // Lasso: Shift + right button — start freehand polygon
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
      // Lasso update — append point to freehand path
      if (lassoRef.current) {
        const r = c.getBoundingClientRect();
        const x = e.clientX - r.left, y = e.clientY - r.top;
        lassoRef.current.points.push({ x, y });
        // Only re-render every 3rd point to reduce React state updates
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
      // Lasso finish — point-in-polygon test for all nodes
      if (lassoRef.current) {
        const pts = lassoRef.current.points;
        if (pts.length >= 3) {
          const t = tRef.current;
          // Winding-number point-in-polygon (non-zero = inside, gives union on self-overlap)
          function inPolygon(px, py) {
            let wn = 0;
            for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {
              const xi = pts[i].x, yi = pts[i].y, xj = pts[j].x, yj = pts[j].y;
              if (yj <= py) {
                if (yi > py && ((xi - xj) * (py - yj) - (px - xj) * (yi - yj)) > 0) wn++;
              } else {
                if (yi <= py && ((xi - xj) * (py - yj) - (px - xj) * (yi - yj)) < 0) wn--;
              }
            }
            return wn !== 0;
          }
          const selected = nRef.current
            .filter(n => {
              if (n.x == null || n.y == null) return false;
              const sx = n.x * t.k + t.x;
              const sy = n.y * t.k + t.y;
              return inPolygon(sx, sy);
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

    // Click (only fires if no drag happened)
    function onClick(e) {
      if (didDrag) { didDrag = false; return; }
      const r = c.getBoundingClientRect();
      const mx = e.clientX - r.left, my = e.clientY - r.top;
      const n = gN(mx, my);
      // Pathfind pick-target mode: clicking a node completes the pathfind
      if (pathfindSourceRef.current && n) {
        onPathfindTargetRef.current?.(n.id);
        return;
      }
      if (n) { onSelRef.current('node', n.id, e.shiftKey); return; }
      const ed = gE(mx, my);
      if (ed) { onSelRef.current('edge', ed, false); return; }
      // Clicking empty canvas clears both selection and query highlight
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
      // Suppress context menu if a lasso drag just finished
      if (lassoRef.current) return;
      const r = c.getBoundingClientRect();
      const cx = e.clientX - r.left;
      const cy = e.clientY - r.top;
      const n = gN(cx, cy);
      if (n) {
        const label = n.metadata?.name || (n.hostnames?.length ? n.hostnames[0] : n.id);
        setCtxMenu({ x: cx, y: cy, nodeId: n.id, nodeLabel: label, isSynthetic: !!n.synthetic, isCluster: !!n.is_cluster, isSubnet: !!n.is_subnet, clusterId: n.cluster_id, canvasX: null, canvasY: null, edgeId: null });
      } else {
        // Check if we right-clicked an edge
        const ed = gE(cx, cy);
        if (ed) {
          setCtxMenu({ x: cx, y: cy, nodeId: null, nodeLabel: null, edgeId: ed.id, isSyntheticEdge: !!ed.synthetic, canvasX: null, canvasY: null });
        } else {
          // Empty canvas — store graph-space coords for annotation placement
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

  // ── Mini components ─────────────────────────────────────────────
  function MenuItem({ icon, onClick, children }) {
    return (
      <div onClick={onClick} style={{ padding: '7px 12px', fontSize: 12, color: 'var(--tx)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }}
        onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,.1)'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
        {icon}<span>{children}</span>
      </div>
    );
  }
  function MenuDivider() {
    return <div style={{ height: 1, background: 'var(--bd)', margin: '3px 0' }} />;
  }

  // ── Synthetic node form ──────────────────────────────────────────
  function SyntheticNodeForm({ onClose }) {
    const [ip, setIp] = React.useState('');
    const [label, setLabel] = React.useState('');
    const [color, setColor] = React.useState('#f0883e');
    return (
      <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', zIndex: 200,
        background: 'var(--bgP)', border: '1px solid var(--bdL)', borderRadius: 10, padding: '16px 20px', minWidth: 260,
        boxShadow: '0 8px 32px rgba(0,0,0,.5)', fontFamily: 'var(--fn)',
      }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--tx)', marginBottom: 12 }}>Add Synthetic Node</div>
        {[['IP / ID', ip, setIp, 'e.g. 10.0.0.99'],['Label', label, setLabel, 'Optional display name']].map(([lbl, val, set, ph]) => (
          <div key={lbl} style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 3 }}>{lbl}</div>
            <input value={val} onChange={e => set(e.target.value)} placeholder={ph}
              style={{ width: '100%', boxSizing: 'border-box', padding: '5px 8px', fontSize: 11, background: 'var(--bgI)', border: '1px solid var(--bd)', borderRadius: 4, color: 'var(--tx)', fontFamily: 'var(--fn)', outline: 'none' }} />
          </div>
        ))}
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 3 }}>Color</div>
          <div style={{ display: 'flex', gap: 6 }}>
            {['#f0883e','#58a6ff','#3fb950','#bc8cff','#f78166','#e3b341'].map(c => (
              <div key={c} onClick={() => setColor(c)} style={{ width: 18, height: 18, borderRadius: '50%', background: c, cursor: 'pointer', border: color === c ? '2px solid white' : '2px solid transparent' }} />
            ))}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button className="btn" onClick={onClose} style={{ fontSize: 10 }}>Cancel</button>
          <button className="btn" onClick={() => {
            if (!ip.trim()) return;
            onAddSyntheticNode?.({ ip: ip.trim(), label: label.trim() || ip.trim(), color });
            onClose();
          }} style={{ fontSize: 10, background: 'rgba(63,185,80,.1)', borderColor: '#3fb950', color: '#3fb950' }}>Add Node</button>
        </div>
        <div style={{ marginTop: 10, fontSize: 9, color: 'var(--txD)' }}>
          Synthetic nodes render with a dashed border and ✦ marker. They are saved to the backend and persist across page reloads.
        </div>
      </div>
    );
  }

  // ── Synthetic edge form ──────────────────────────────────────────
  function SyntheticEdgeForm({ onClose }) {
    const [src, setSrc] = React.useState(synEdgeSrc);
    const [tgt, setTgt] = React.useState('');
    const [protocol, setProtocol] = React.useState('');
    const [label, setLabel] = React.useState('');
    const [color, setColor] = React.useState('#f0883e');
    const [focusedField, setFocusedField] = React.useState(null); // 'src' | 'tgt'

    // Build a display-friendly node list: label (or id) + id
    const allNodes = nRef.current.map(n => ({
      id: n.id,
      label: n.metadata?.name || (n.hostnames?.length ? n.hostnames[0] : null) || n.id,
    }));

    function NodePicker({ onPick }) {
      return (
        <div style={{
          maxHeight: 140, overflowY: 'auto', border: '1px solid var(--bd)',
          borderRadius: 4, marginTop: 4, background: 'var(--bgC)',
        }}>
          {allNodes.length === 0 && (
            <div style={{ padding: '6px 8px', fontSize: 10, color: 'var(--txD)' }}>No nodes in current graph</div>
          )}
          {allNodes.map(n => (
            <div key={n.id} onClick={() => onPick(n.id)}
              style={{ padding: '4px 8px', fontSize: 10, cursor: 'pointer', borderBottom: '1px solid var(--bd)', display: 'flex', justifyContent: 'space-between', gap: 8 }}
              onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,.1)'}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
            >
              <span style={{ color: 'var(--txM)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{n.label}</span>
              {n.label !== n.id && <span style={{ color: 'var(--txD)', fontSize: 9, flexShrink: 0 }}>{n.id.length > 20 ? n.id.slice(0,18) + '…' : n.id}</span>}
            </div>
          ))}
        </div>
      );
    }

    return (
      <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', zIndex: 200,
        background: 'var(--bgP)', border: '1px solid var(--bdL)', borderRadius: 10, padding: '16px 20px', minWidth: 300, maxWidth: 360,
        boxShadow: '0 8px 32px rgba(0,0,0,.5)', fontFamily: 'var(--fn)',
      }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--tx)', marginBottom: 12 }}>Add Synthetic Edge</div>

        {/* Source */}
        <div style={{ marginBottom: 10 }}>
          <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 3 }}>Source node <span style={{ color: 'var(--acR)' }}>*</span></div>
          <input value={src} onChange={e => setSrc(e.target.value)}
            onFocus={() => setFocusedField('src')} onBlur={() => setTimeout(() => setFocusedField(f => f === 'src' ? null : f), 150)}
            placeholder="Click a node below or type ID"
            style={{ width: '100%', boxSizing: 'border-box', padding: '5px 8px', fontSize: 11, background: src ? 'rgba(88,166,255,.07)' : 'var(--bgI)', border: `1px solid ${src ? 'var(--ac)' : 'var(--bd)'}`, borderRadius: 4, color: 'var(--tx)', fontFamily: 'var(--fn)', outline: 'none' }} />
          {(focusedField === 'src' || !src) && <NodePicker onPick={id => { setSrc(id); setFocusedField(null); }} />}
        </div>

        {/* Target */}
        <div style={{ marginBottom: 10 }}>
          <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 3 }}>Target node <span style={{ color: 'var(--acR)' }}>*</span></div>
          <input value={tgt} onChange={e => setTgt(e.target.value)}
            onFocus={() => setFocusedField('tgt')} onBlur={() => setTimeout(() => setFocusedField(f => f === 'tgt' ? null : f), 150)}
            placeholder="Click a node below or type ID"
            style={{ width: '100%', boxSizing: 'border-box', padding: '5px 8px', fontSize: 11, background: tgt ? 'rgba(88,166,255,.07)' : 'var(--bgI)', border: `1px solid ${tgt ? 'var(--ac)' : 'var(--bd)'}`, borderRadius: 4, color: 'var(--tx)', fontFamily: 'var(--fn)', outline: 'none' }} />
          {(focusedField === 'tgt' || !tgt) && <NodePicker onPick={id => { setTgt(id); setFocusedField(null); }} />}
        </div>

        {/* Protocol + label */}
        {[['Protocol (optional)', protocol, setProtocol, 'e.g. HTTPS'],['Label (optional)', label, setLabel, 'Description']].map(([lbl, val, set, ph]) => (
          <div key={lbl} style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 3 }}>{lbl}</div>
            <input value={val} onChange={e => set(e.target.value)} placeholder={ph}
              style={{ width: '100%', boxSizing: 'border-box', padding: '5px 8px', fontSize: 11, background: 'var(--bgI)', border: '1px solid var(--bd)', borderRadius: 4, color: 'var(--tx)', fontFamily: 'var(--fn)', outline: 'none' }} />
          </div>
        ))}

        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 10, color: 'var(--txD)', marginBottom: 3 }}>Color</div>
          <div style={{ display: 'flex', gap: 6 }}>
            {['#f0883e','#58a6ff','#3fb950','#bc8cff','#f78166','#e3b341'].map(col => (
              <div key={col} onClick={() => setColor(col)} style={{ width: 18, height: 18, borderRadius: '50%', background: col, cursor: 'pointer', border: color === col ? '2px solid white' : '2px solid transparent' }} />
            ))}
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button className="btn" onClick={onClose} style={{ fontSize: 10 }}>Cancel</button>
          <button className="btn" disabled={!src.trim() || !tgt.trim()} onClick={() => {
            onAddSyntheticEdge?.({ source: src.trim(), target: tgt.trim(), protocol: protocol.trim() || 'SYNTHETIC', label: label.trim(), color });
            onClose();
          }} style={{ fontSize: 10, background: 'rgba(63,185,80,.1)', borderColor: '#3fb950', color: '#3fb950', opacity: (!src.trim() || !tgt.trim()) ? 0.4 : 1 }}>Add Edge</button>
        </div>

        <div style={{ marginTop: 8, fontSize: 9, color: 'var(--txD)', lineHeight: 1.5 }}>
          Dashed line between the two nodes. Tip: right-click any node → "Draw synthetic edge from here" to pre-fill the source.
        </div>
      </div>
    );
  }

  return (
    <div style={{ width: '100%', height: '100%', position: 'relative' }}>
      <canvas ref={cRef} style={{ width: '100%', height: '100%', display: 'block', cursor: pathfindSource ? 'crosshair' : undefined }} />

      {/* Export PNG button */}
      <button onClick={doExportPNG} title="Export graph as PNG"
        style={{
          position: 'absolute', bottom: 84, right: 12, zIndex: 10,
          display: 'flex', alignItems: 'center', gap: 5,
          background: 'rgba(14,17,23,.85)', border: '1px solid var(--bdL)',
          borderRadius: 6, padding: '5px 10px', fontSize: 10,
          color: 'var(--txM)', cursor: 'pointer', fontFamily: 'var(--fn)',
        }}>
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
        </svg>
        Export PNG
      </button>

      {/* Relayout button — bottom-right of graph (avoids overlap with hidden nodes badge) */}
      <button onClick={doRelayout} title="Reset layout — unpins all nodes and re-runs the force simulation"
        style={{
          position: 'absolute', bottom: 48, right: 12, zIndex: 10,
          display: 'flex', alignItems: 'center', gap: 5,
          background: 'rgba(14,17,23,.85)', border: '1px solid var(--bdL)',
          borderRadius: 6, padding: '5px 10px', fontSize: 10,
          color: 'var(--txM)', cursor: 'pointer', fontFamily: 'var(--fn)',
        }}>
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polyline points="1 4 1 10 7 10"/><polyline points="23 20 23 14 17 14"/>
          <path d="M20.49 9A9 9 0 005.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 013.51 15"/>
        </svg>
        Relayout
      </button>

      {/* Lasso selection overlay — freehand SVG polygon */}
      {lasso && lasso.points?.length >= 2 && (
        <svg style={{
          position: 'absolute', inset: 0, width: '100%', height: '100%',
          pointerEvents: 'none', zIndex: 5, overflow: 'visible',
        }}>
          <polygon
            points={lasso.points.map(p => `${p.x},${p.y}`).join(' ')}
            fill="rgba(88,166,255,0.07)"
            stroke="var(--ac)"
            strokeWidth="1.5"
            strokeDasharray="5,3"
            strokeLinejoin="round"
          />
        </svg>
      )}
      {ctxMenu && (
        <>
          {/* Dismiss overlay */}
          <div
            style={{ position: 'absolute', inset: 0, zIndex: 99 }}
            onClick={() => setCtxMenu(null)}
            onContextMenu={e => { e.preventDefault(); setCtxMenu(null); }}
          />
          {/* Menu */}
          <div ref={menuRef} style={{
            position: 'absolute',
            left: ctxMenu.x + 2,
            top: ctxMenu.y + 2,
            zIndex: 100,
            background: 'var(--bgC)',
            border: '1px solid var(--bdL)',
            borderRadius: 7,
            padding: '4px 0',
            minWidth: 170,
            boxShadow: '0 4px 16px rgba(0,0,0,.4)',
            fontFamily: 'var(--fn)',
          }}>
            {ctxMenu.nodeId ? (
            <>
            {/* ── Node / Cluster context menu ── */}
            <div style={{
              padding: '5px 12px 6px', borderBottom: '1px solid var(--bd)',
              fontSize: 10, color: 'var(--txD)',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              display: 'flex', alignItems: 'center', gap: 4,
            }}>
              {ctxMenu.isSynthetic && <span style={{ fontSize: 8, color: '#f0883e', border: '1px solid #f0883e', borderRadius: 3, padding: '0 3px' }}>synthetic</span>}
              {ctxMenu.isCluster && <span style={{ fontSize: 8, color: '#bc8cff', border: '1px solid #bc8cff', borderRadius: 3, padding: '0 3px' }}>cluster</span>}
              {ctxMenu.nodeLabel}
            </div>

            {/* INSPECT */}
            <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--txM)" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>}
              onClick={() => { onSelRef.current('node', ctxMenu.nodeId, false); setCtxMenu(null); }}>
              {ctxMenu.isCluster ? 'Cluster detail' : 'Node detail'}
            </MenuItem>

            <MenuDivider />

            {/* INVESTIGATE */}
            <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>}
              onClick={() => { onInvNbRef.current?.(ctxMenu.nodeId); setCtxMenu(null); }}>Investigate neighbours</MenuItem>
            {!ctxMenu.isCluster && (
              <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#2dd4bf" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg>}
                onClick={() => { onInvRef.current?.(ctxMenu.nodeId); setCtxMenu(null); }}>Isolate connected graph</MenuItem>
            )}

            <MenuDivider />

            {/* PATHFINDING (not available on cluster/subnet mega-nodes) */}
            {!ctxMenu.isCluster && !ctxMenu.isSubnet && (
              <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#e3b341" strokeWidth="2"><circle cx="5" cy="19" r="3"/><circle cx="19" cy="5" r="3"/><path d="M5 16V9a4 4 0 014-4h6"/><polyline points="15 1 19 5 15 9"/></svg>}
                onClick={() => { onStartPathfind?.(ctxMenu.nodeId); setCtxMenu(null); }}>Find paths to…</MenuItem>
            )}

            {/* EXPAND (cluster only) */}
            {ctxMenu.isCluster && (
              <>
                <MenuDivider />
                <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#d29922" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>}
                  onClick={() => { onExpandCluster?.(ctxMenu.clusterId); setCtxMenu(null); }}>Expand cluster</MenuItem>
              </>
            )}

            {/* UNCLUSTER (subnet only) */}
            {ctxMenu.isSubnet && (
              <>
                <MenuDivider />
                <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#d29922" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>}
                  onClick={() => { onUnclusterSubnet?.(ctxMenu.nodeId); setCtxMenu(null); }}>Uncluster subnet</MenuItem>
              </>
            )}

            <MenuDivider />

            {/* ANNOTATE */}
            <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" strokeWidth="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>}
              onClick={() => { onAddNodeAnnotation?.(ctxMenu.nodeId, ctxMenu.nodeLabel); setCtxMenu(null); }}>Add annotation</MenuItem>

            <MenuDivider />

            {/* EDIT */}
            <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--txD)" strokeWidth="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>}
              onClick={() => { onHideNode?.(ctxMenu.nodeId); setCtxMenu(null); }}>{ctxMenu.isCluster ? 'Hide cluster' : 'Hide node'}</MenuItem>
            {!ctxMenu.isCluster && (
              <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#3fb950" strokeWidth="2"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>}
                onClick={() => { setSynEdgeSrc(ctxMenu.nodeId); setCtxMenu(null); setShowSyntheticEdgeForm(true); }}>Draw edge from here</MenuItem>
            )}
            {ctxMenu.isSynthetic && (
              <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--acR)" strokeWidth="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>}
                onClick={() => { onDeleteSynthetic?.(ctxMenu.nodeId); setCtxMenu(null); }}>Delete synthetic</MenuItem>
            )}
            </>
          ) : ctxMenu.edgeId ? (
            <>
            {/* ── Edge context menu ── */}
            <div style={{
              padding: '5px 12px 6px', borderBottom: '1px solid var(--bd)',
              fontSize: 10, color: 'var(--txD)',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              display: 'flex', alignItems: 'center', gap: 4,
            }}>
              {ctxMenu.isSyntheticEdge && <span style={{ fontSize: 8, color: '#f0883e', border: '1px solid #f0883e', borderRadius: 3, padding: '0 3px' }}>synthetic</span>}
              Edge
            </div>

            {/* INSPECT */}
            <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--txM)" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>}
              onClick={() => { const ed = eRef.current.find(e => e.id === ctxMenu.edgeId); if (ed) onSelRef.current('edge', ed, false); setCtxMenu(null); }}>Edge detail</MenuItem>

            <MenuDivider />

            {/* ANNOTATE */}
            <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#bc8cff" strokeWidth="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>}
              onClick={() => { onAddEdgeAnnotation?.(ctxMenu.edgeId); setCtxMenu(null); }}>Add annotation</MenuItem>

            {/* EDIT */}
            {ctxMenu.isSyntheticEdge && (
              <>
                <MenuDivider />
                <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--acR)" strokeWidth="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>}
                  onClick={() => { onDeleteSynthetic?.(ctxMenu.edgeId); setCtxMenu(null); }}>Delete synthetic</MenuItem>
              </>
            )}
            </>
          ) : (
            <>
            {/* ── Empty canvas menu ── */}

            {/* SELECTION */}
            {selNRef.current.size >= 2 && (
              <>
                <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#bc8cff" strokeWidth="2"><circle cx="5" cy="12" r="2"/><circle cx="12" cy="5" r="2"/><circle cx="19" cy="12" r="2"/><circle cx="12" cy="19" r="2"/><line x1="7" y1="12" x2="10" y2="12"/><line x1="12" y1="7" x2="12" y2="10"/><line x1="14" y1="12" x2="17" y2="12"/><line x1="12" y1="14" x2="12" y2="17"/></svg>}
                  onClick={() => {
                    onCreateManualCluster?.(Array.from(selNRef.current));
                    setCtxMenu(null);
                  }}>Group selected ({selNRef.current.size} nodes)</MenuItem>
                <MenuDivider />
              </>
            )}

            {/* CREATE */}
            <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#f0883e" strokeWidth="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>}
              onClick={() => { onAddAnnotation?.(ctxMenu.canvasX, ctxMenu.canvasY); setCtxMenu(null); }}>Add annotation</MenuItem>
            <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#3fb950" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>}
              onClick={() => { setCtxMenu(null); setShowSyntheticNodeForm(true); }}>Add synthetic node</MenuItem>
            <MenuItem icon={<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#3fb950" strokeWidth="2"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>}
              onClick={() => { setCtxMenu(null); setShowSyntheticEdgeForm(true); setSynEdgeSrc(''); }}>Add synthetic edge</MenuItem>
            </>
          )}
          </div>
        </>
      )}

      {/* Synthetic node/edge creation forms (modal overlays) */}
      {showSyntheticNodeForm && (
        <>
          <div style={{ position: 'absolute', inset: 0, zIndex: 199, background: 'rgba(0,0,0,.45)' }}
            onClick={() => setShowSyntheticNodeForm(false)} />
          <SyntheticNodeForm onClose={() => setShowSyntheticNodeForm(false)} />
        </>
      )}
      {showSyntheticEdgeForm && (
        <>
          <div style={{ position: 'absolute', inset: 0, zIndex: 199, background: 'rgba(0,0,0,.45)' }}
            onClick={() => setShowSyntheticEdgeForm(false)} />
          <SyntheticEdgeForm onClose={() => setShowSyntheticEdgeForm(false)} />
        </>
      )}

      {/* Annotation overlays — HTML labels pinned to graph-space coords */}
      {/* Canvas annotations use absolute position from graph-space coords.   */}
      {/* Node/edge annotations are displayed near the node/edge at render    */}
      {/* time; x/y are ignored for those (node_id/edge_id takes precedence). */}
      {annotations.map(ann => {
        const t = tRef.current;
        let sx, sy;
        if (ann.node_id) {
          // Find the node's current canvas position
          const node = nRef.current.find(n => n.id === ann.node_id);
          if (!node) return null;
          sx = node.x * t.k + t.x;
          sy = (node.y - 30) * t.k + t.y; // above the node
        } else if (ann.edge_id) {
          // Find the edge midpoint
          const edge = eRef.current.find(e => e.id === ann.edge_id);
          if (!edge) return null;
          const src = typeof edge.source === 'object' ? edge.source : nRef.current.find(n => n.id === edge.source);
          const tgt = typeof edge.target === 'object' ? edge.target : nRef.current.find(n => n.id === edge.target);
          if (!src || !tgt) return null;
          sx = ((src.x + tgt.x) / 2) * t.k + t.x;
          sy = ((src.y + tgt.y) / 2 - 20) * t.k + t.y;
        } else {
          sx = ann.x * t.k + t.x;
          sy = ann.y * t.k + t.y;
        }
        return (
          <div key={ann.id} style={{
            position: 'absolute', left: sx, top: sy, zIndex: 50,
            transform: 'translate(-50%, -100%)',
            pointerEvents: 'auto',
          }}>
            {editingAnn === ann.id ? (
              <input
                autoFocus
                defaultValue={ann.label}
                onBlur={e => {
                  const val = e.target.value.trim();
                  if (val) onUpdateAnnotation?.(ann.id, { label: val });
                  else onDeleteAnnotation?.(ann.id);
                  setEditingAnn(null);
                }}
                onKeyDown={e => {
                  if (e.key === 'Enter') e.target.blur();
                  if (e.key === 'Escape') { setEditingAnn(null); }
                }}
                style={{
                  background: 'var(--bgP)', border: `1px solid ${ann.color}`,
                  borderRadius: 4, padding: '2px 6px',
                  fontSize: Math.round(Math.max(8, Math.min(16, 11 * t.k))),
                  color: 'var(--tx)', fontFamily: 'var(--fn)', outline: 'none',
                  minWidth: 80,
                }}
              />
            ) : (
              <div
                onDoubleClick={() => setEditingAnn(ann.id)}
                style={{
                  background: 'var(--bgP)', border: `1px solid ${ann.color}`,
                  borderRadius: 4, padding: '2px 8px',
                  // Scale font with zoom but clamp so labels don't become illegibly tiny
                  // at extreme zoom-out or absurdly huge at extreme zoom-in.
                  fontSize: Math.round(Math.max(8, Math.min(16, 11 * t.k))),
                  color: ann.color, fontFamily: 'var(--fn)',
                  cursor: 'pointer', whiteSpace: 'nowrap',
                  boxShadow: '0 2px 6px rgba(0,0,0,.3)',
                  display: 'flex', alignItems: 'center', gap: 5,
                }}
              >
                {ann.node_id && <span style={{ fontSize: 8, opacity: 0.6 }}>⬤ </span>}
                {ann.edge_id && <span style={{ fontSize: 8, opacity: 0.6 }}>— </span>}
                {ann.label}
                <span
                  onClick={e => { e.stopPropagation(); onDeleteAnnotation?.(ann.id); }}
                  style={{ color: 'var(--txD)', fontSize: 9, cursor: 'pointer', marginLeft: 2 }}
                >✕</span>
              </div>
            )}
            {/* Pin line — only for canvas annotations (node/edge ones anchor differently) */}
            {!ann.node_id && !ann.edge_id && (
              <div style={{
                position: 'absolute', left: '50%', top: '100%',
                width: 1, height: 8, background: ann.color, opacity: 0.6,
                transform: 'translateX(-50%)',
              }} />
            )}
          </div>
        );
      })}
    </div>
  );
}
