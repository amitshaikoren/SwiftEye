/**
 * useSelectionAndNavigation — selection state, nav history, investigation,
 * pathfinding, hidden nodes, panel resize.
 *
 * Extracted from useCapture as part of the decomposition (v0.25.0).
 *
 * Cross-slice params:
 *   - search, setSearch (from filters — for clearAll and nav restore)
 *   - graph (from data — for investigate/pathfind neighbour traversal)
 */

import { useState, useRef, useEffect, useCallback } from 'react';
import { fetchPaths } from '../api';

export function useSelectionAndNavigation({ search, setSearch, graph }) {

  // ── Selection state ──────────────────────────────────────────────

  const [selNodes, setSelNodes]   = useState([]);
  const [selEdge, setSelEdge]     = useState(null);
  const [selSession, setSelSession] = useState(null);
  const [selSessionSiblings, setSelSessionSiblings] = useState([]);
  const [rPanel, setRPanel]       = useState('stats');

  // ── Navigation history (back/forward) ────────────────────────────

  const navHistoryRef = useRef([]);
  const navIndexRef = useRef(-1);
  const navRestoringRef = useRef(false);

  // Always holds latest state for snapshot accuracy
  const latestRef = useRef({});
  latestRef.current = { selNodes, selEdge, selSession, selSessionSiblings, rPanel, search };

  function _navSnapshot() {
    const s = latestRef.current;
    return { selNodes: [...s.selNodes], selEdge: s.selEdge, selSession: s.selSession, selSessionSiblings: [...s.selSessionSiblings], rPanel: s.rPanel, search: s.search };
  }
  function _navPush() {
    if (navRestoringRef.current) return;
    const snap = _navSnapshot();
    navHistoryRef.current = navHistoryRef.current.slice(0, navIndexRef.current + 1);
    navHistoryRef.current.push(snap);
    if (navHistoryRef.current.length > 50) navHistoryRef.current.shift();
    navIndexRef.current = navHistoryRef.current.length - 1;
  }
  function _navRestore(snap) {
    navRestoringRef.current = true;
    setSelNodes(snap.selNodes);
    setSelEdge(snap.selEdge);
    setSelSession(snap.selSession);
    setSelSessionSiblings(snap.selSessionSiblings);
    setRPanel(snap.rPanel);
    setSearch(snap.search);
    setTimeout(() => { navRestoringRef.current = false; }, 0);
  }
  function navBack() {
    if (navIndexRef.current <= 0) return;
    if (navIndexRef.current === navHistoryRef.current.length - 1) {
      const snap = _navSnapshot();
      navHistoryRef.current.push(snap);
    }
    navIndexRef.current--;
    _navRestore(navHistoryRef.current[navIndexRef.current]);
  }
  function navForward() {
    if (navIndexRef.current >= navHistoryRef.current.length - 1) return;
    navIndexRef.current++;
    _navRestore(navHistoryRef.current[navIndexRef.current]);
  }
  const canGoBack = navHistoryRef.current.length > 0 && navIndexRef.current > 0;
  const canGoForward = navIndexRef.current < navHistoryRef.current.length - 1;

  // ── Investigation & hidden nodes ─────────────────────────────────

  const [investigatedIp, setInvestigatedIp]       = useState('');
  const [investigationNodes, setInvestigationNodes] = useState(null);
  const [hiddenNodes, setHiddenNodes]             = useState(new Set());

  // ── Pathfinding ──────────────────────────────────────────────────

  const [pathfindSource, setPathfindSource]       = useState(null);
  const [pathfindResult, setPathfindResult]       = useState(null);
  const [pathfindLoading, setPathfindLoading]     = useState(false);
  const [seqAckSessionId, setSeqAckSessionId]     = useState('');

  // Per-session collapse state memory
  const collapseStatesRef = useRef(new Map());

  // ── Panel resize ─────────────────────────────────────────────────

  const [panelWidth, setPanelWidth] = useState(330);
  const panelDragRef = useRef(null);

  // ── Escape handler (mount-only) ──────────────────────────────────

  useEffect(() => {
    const h = e => { if (e.key === 'Escape') clearAll(); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Selection handlers ───────────────────────────────────────────

  function clearSel() { setSelNodes([]); setSelEdge(null); setSelSession(null); }
  function clearAll() { _navPush(); clearSel(); setSearch(''); }

  function handleGSel(type, data, shift) {
    if (type === 'node') {
      _navPush();
      if (shift) {
        setSelNodes(p => p.includes(data) ? p.filter(n => n !== data) : [...p, data]);
        setSelEdge(null); setSelSession(null); setRPanel('detail');
      } else {
        setSelNodes([data]); setSelEdge(null); setSelSession(null); setRPanel('detail');
      }
    } else if (type === 'edge') {
      _navPush();
      setSelEdge(data); setSelNodes([]); setSelSession(null); setRPanel('edge');
    } else {
      clearAll();
    }
  }

  function selectSession(s)     { _navPush(); setSelSession(s); setSelSessionSiblings([]); setSelNodes([]); setSelEdge(null); setRPanel('session'); }
  function selectSessionWithContext(s, siblings) {
    _navPush();
    const sorted = [...(siblings || [])].sort((a, b) => (a.start_time || 0) - (b.start_time || 0));
    setSelSession(s);
    setSelSessionSiblings(sorted);
    setSelNodes([]);
    setSelEdge(null);
    setRPanel('session');
  }
  function selectNodePanel(id)  { _navPush(); setSelNodes([id]); setSelEdge(null); setSelSession(null); setRPanel('detail'); }
  function switchPanel(k)       { _navPush(); clearSel(); setRPanel(k); }

  // ── Investigation ────────────────────────────────────────────────

  function handleInvestigate(nodeId) {
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];
    const adj = new Map();
    nodes.forEach(n => adj.set(n.id, new Set()));
    edges.forEach(e => {
      const s = typeof e.source === 'object' ? e.source.id : e.source;
      const t = typeof e.target === 'object' ? e.target.id : e.target;
      if (adj.has(s)) adj.get(s).add(t);
      if (adj.has(t)) adj.get(t).add(s);
    });
    const visited = new Set([nodeId]);
    const queue = [nodeId];
    while (queue.length) {
      const cur = queue.shift();
      for (const nb of (adj.get(cur) || [])) {
        if (!visited.has(nb)) { visited.add(nb); queue.push(nb); }
      }
    }
    const node = nodes.find(n => n.id === nodeId);
    setInvestigatedIp(node?.ips?.[0] || nodeId);
    setInvestigationNodes(visited);
    clearSel();
  }

  function handleInvestigateNeighbours(nodeId) {
    const edges = graph.edges || [];
    const visited = new Set([nodeId]);
    edges.forEach(e => {
      const s = typeof e.source === 'object' ? e.source.id : e.source;
      const t = typeof e.target === 'object' ? e.target.id : e.target;
      if (s === nodeId) visited.add(t);
      if (t === nodeId) visited.add(s);
    });
    const node = (graph.nodes || []).find(n => n.id === nodeId);
    setInvestigatedIp(node?.ips?.[0] || nodeId);
    setInvestigationNodes(visited);
    clearSel();
  }

  function exitInvestigation() {
    setInvestigatedIp('');
    setInvestigationNodes(null);
    setPathfindSource(null);
    setPathfindResult(null);
  }

  // ── Pathfinding ──────────────────────────────────────────────────

  function startPathfind(sourceNodeId) {
    setPathfindSource(sourceNodeId);
    setPathfindResult(null);
  }

  function cancelPathfind() {
    setPathfindSource(null);
    setPathfindResult(null);
  }

  async function executePathfind(targetNodeId, opts = {}) {
    const src = opts.source || pathfindSource;
    if (!src || src === targetNodeId) return;
    setPathfindLoading(true);
    try {
      const data = await fetchPaths(src, targetNodeId, { directed: opts.directed || false });
      setPathfindResult(data);
      if (data.path_count > 0) {
        setInvestigationNodes(new Set(data.nodes || []));
        setInvestigatedIp(`${data.source} → ${data.target}`);
      }
    } catch (err) {
      console.error('Pathfinding failed:', err);
      setPathfindResult({ source: src, target: targetNodeId, directed: false, path_count: 0, hop_layers: {}, edges: [], nodes: [] });
    } finally {
      setPathfindLoading(false);
      setPathfindSource(null);
    }
  }

  function runPathfindFromPanel(source, target, opts = {}) {
    executePathfind(target, { source, directed: opts.directed || false });
  }

  // ── Hide nodes ───────────────────────────────────────────────────

  function handleHideNode(nodeId) {
    setHiddenNodes(prev => {
      if (prev.has(nodeId)) return prev;
      const n = new Set(prev); n.add(nodeId); return n;
    });
    clearSel();
  }
  function handleUnhideAll() {
    setHiddenNodes(prev => prev.size === 0 ? prev : new Set());
  }

  // ── Panel resize ─────────────────────────────────────────────────

  function handlePanelDragStart(e) {
    e.preventDefault();
    panelDragRef.current = { startX: e.clientX, startW: panelWidth };
    const onMove = ev => {
      const delta = panelDragRef.current.startX - ev.clientX;
      setPanelWidth(Math.max(220, Math.min(600, panelDragRef.current.startW + delta)));
    };
    const onUp = () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      panelDragRef.current = null;
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
    document.body.style.cursor = 'ew-resize';
    document.body.style.userSelect = 'none';
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
  }

  // ── Cross-slice callbacks (called via refs from other slices) ────

  const clearPathfindState = useCallback(() => {
    setPathfindResult(null);
    setPathfindSource(null);
    setInvestigatedIp('');
    setInvestigationNodes(null);
  }, []);

  // clearSel is already defined above — used by filters' handleCreateManualCluster

  return {
    selNodes, selEdge, selSession, selSessionSiblings, rPanel,
    handleGSel, selectSession, selectSessionWithContext, selectNodePanel, switchPanel,
    clearSel, clearAll,
    navBack, navForward, canGoBack, canGoForward,
    handleInvestigate, handleInvestigateNeighbours, exitInvestigation,
    investigatedIp, investigationNodes,
    hiddenNodes, handleHideNode, handleUnhideAll,
    pathfindSource, startPathfind, cancelPathfind, executePathfind,
    pathfindResult, pathfindLoading, runPathfindFromPanel,
    seqAckSessionId, setSeqAckSessionId,
    collapseStatesRef,
    panelWidth, setPanelWidth, handlePanelDragStart,
    clearPathfindState,
  };
}
