/**
 * useCapture — all capture-related state, data fetching, and handlers.
 *
 * This hook owns everything that depends on a loaded pcap file:
 *   - Capture lifecycle (upload, load, status)
 *   - Graph / sessions / timeline / stats / protocols
 *   - Filters (search, time range, protocol toggle, subnet, merge, IPv6)
 *   - Display filter (client-side Wireshark-style)
 *   - Annotations and synthetic elements
 *   - Selection state (node, edge, session)
 *   - Investigation mode and hidden nodes
 *   - Right-panel routing
 *
 * App.jsx imports this hook and passes its return values directly to components.
 * No business logic lives in App.jsx — it is pure layout and routing.
 */

import { useState, useEffect, useRef, useMemo } from 'react';
import {
  fetchStatus, fetchStats, slicePcapUrl,
  fetchTimeline, fetchProtocols, fetchSessions,
  fetchPluginResults, fetchPluginSlots, fetchGraph,
  uploadPcap, uploadMetadata,
  fetchAnnotations, createAnnotation, updateAnnotation, deleteAnnotation,
  fetchSynthetic, createSynthetic, updateSynthetic, deleteSynthetic,
} from '../api';
import { fTtime } from '../utils';
import { applyDisplayFilter } from '../displayFilter';

export function useCapture() {

  // ── Capture lifecycle ────────────────────────────────────────────
  const [loaded, setLoaded]   = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadMsg, setLoadMsg] = useState('');
  const [error, setError]     = useState('');
  const [fileName, setFileName] = useState('');
  const [sourceFiles, setSourceFiles] = useState([]);

  // ── Server data ──────────────────────────────────────────────────
  const [stats, setStats]           = useState(null);
  const [timeline, setTimeline]     = useState([]);
  const [graph, setGraph]           = useState({ nodes: [], edges: [] });
  const [sessions, setSessions]     = useState([]);
  const [sessionTotal, setSessionTotal] = useState(0);
  const [protocols, setProtocols]   = useState([]);
  const [pColors, setPColors]       = useState({});
  const [pluginResults, setPluginResults] = useState({});
  const [pluginSlots, setPluginSlots]     = useState([]);

  // ── Filters ──────────────────────────────────────────────────────
  const [timeRange, setTimeRange]   = useState([0, 0]);
  const [enabledP, setEnabledP]     = useState(new Set());
  const [search, setSearch]         = useState('');
  const [bucketSec, setBucketSec]   = useState(15);
  const [subnetG, setSubnetG]       = useState(false);
  const [labelThreshold, setLabelThreshold] = useState(0); // hide labels below this bytes value (0 = show all)

  const [subnetPrefix, setSubnetPrefix] = useState(24);
  const [mergeByMac, setMergeByMac] = useState(false);
  const [includeIPv6, setIncludeIPv6] = useState(true);
  const [showHostnames, setShowHostnames] = useState(true);
  const [subnetExclusions, setSubnetExclusions] = useState(new Set());

  // ── Display filter ────────────────────────────────────────────────
  const [dfExpr, setDfExpr]       = useState('');
  const [dfApplied, setDfApplied] = useState('');
  const [dfError, setDfError]     = useState(null);
  const [dfResult, setDfResult]   = useState(null);

  // ── Annotations & synthetic ───────────────────────────────────────
  const [annotations, setAnnotations] = useState([]);
  const [synthetic, setSynthetic]     = useState([]);

  // ── Selection & UI routing ────────────────────────────────────────
  const [selNodes, setSelNodes]   = useState([]);
  const [selEdge, setSelEdge]     = useState(null);
  const [selSession, setSelSession] = useState(null);
  const [selSessionSiblings, setSelSessionSiblings] = useState([]);  // sorted sibling sessions from edge
  const [rPanel, setRPanel]       = useState('stats');

  // ── Investigation & hidden nodes ─────────────────────────────────
  const [investigatedIp, setInvestigatedIp]       = useState('');
  const [investigationNodes, setInvestigationNodes] = useState(null);
  const [hiddenNodes, setHiddenNodes]             = useState(new Set());
  const [seqAckSessionId, setSeqAckSessionId]     = useState('');

  // ── Panel resize ─────────────────────────────────────────────────
  const [panelWidth, setPanelWidth] = useState(330);
  const panelDragRef = useRef(null);

  // ── Derived: visible nodes/edges (memoised for stable references) ─
  const visibleNodes = useMemo(
    () => (graph.nodes || []).filter(n => !hiddenNodes.has(n.id)),
    [graph.nodes, hiddenNodes]
  );
  const visibleEdges = useMemo(
    () => (graph.edges || []).filter(e => {
      const s = e.source?.id || e.source;
      const t = e.target?.id || e.target;
      return !hiddenNodes.has(s) && !hiddenNodes.has(t);
    }),
    [graph.edges, hiddenNodes]
  );

  const timeLabel = useMemo(() => {
    if (!timeline.length) return '';
    const s = timeline[timeRange[0]], e = timeline[timeRange[1]];
    return s && e ? fTtime(s.start_time) + ' — ' + fTtime(e.end_time) : '';
  }, [timeline, timeRange]);

  const osGuesses = useMemo(
    () => [...new Set((graph.nodes || []).map(n => n.os_guess).filter(Boolean))].sort(),
    [graph.nodes]
  );

  const availableIps = useMemo(
    () => [...new Set((graph.nodes || []).flatMap(n => n.ips || [n.id]).filter(ip => ip && !ip.includes('/')))].sort(),
    [graph.nodes]
  );

  // ── Effects ───────────────────────────────────────────────────────

  // On mount: check if a capture is already loaded server-side
  useEffect(() => {
    fetchStatus().then(d => {
      if (d.capture_loaded) {
        setFileName(d.file_name);
        loadAll();
      }
    }).catch(() => {});
  }, []);

  // Escape to deselect
  useEffect(() => {
    const h = e => { if (e.key === 'Escape') clearSel(); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, []);

  // Re-fetch timeline when bucket size changes
  useEffect(() => {
    if (!loaded) return;
    fetchTimeline(bucketSec).then(d => {
      setTimeline(d.buckets);
      setTimeRange([0, d.buckets.length - 1]);
    }).catch(() => {});
  }, [bucketSec, loaded]);

  // Re-fetch sessions when search or time range changes
  useEffect(() => {
    if (!loaded || !timeline.length) return;
    const ts = timeline[timeRange[0]]?.start_time;
    const te = timeline[timeRange[1]]?.end_time;
    fetchSessions(1000, search, ts != null && te != null ? { timeStart: ts, timeEnd: te } : {})
      .then(d => { setSessions(d.sessions || []); setSessionTotal(d.total ?? d.sessions?.length ?? 0); })
      .catch(() => {});
  }, [search, loaded, timeRange, timeline]);

  // Re-fetch stats when time range changes
  useEffect(() => {
    if (!loaded || !timeline.length) return;
    const ts = timeline[timeRange[0]]?.start_time;
    const te = timeline[timeRange[1]]?.end_time;
    fetchStats(ts != null && te != null ? { timeStart: ts, timeEnd: te } : {})
      .then(d => setStats(d.stats || {}))
      .catch(() => {});
  }, [loaded, timeRange, timeline]);

  // Re-fetch graph when any filter changes
  useEffect(() => {
    if (!loaded || !timeline.length) return;
    const ts = timeline[timeRange[0]]?.start_time;
    const te = timeline[timeRange[1]]?.end_time;
    const params = {};
    if (ts != null) params.timeStart = ts;
    if (te != null) params.timeEnd = te;
    if (enabledP.size < protocols.length && enabledP.size > 0)
      params.protocols = Array.from(enabledP).join(',');
    if (search) params.search = search;
    if (subnetG) { params.subnetGrouping = true; params.subnetPrefix = subnetPrefix; }
    if (mergeByMac)   params.mergeByMac = true;
    if (!includeIPv6) params.includeIPv6 = false;
    if (!showHostnames) params.showHostnames = false;
    if (subnetExclusions.size > 0) params.subnetExclusions = subnetExclusions;

    const ctrl = new AbortController();
    fetchGraph(params, ctrl.signal).then(d => setGraph(d)).catch(e => {
      if (e.name !== 'AbortError') console.error(e);
    });
    return () => ctrl.abort();
  }, [loaded, timeRange, enabledP, search, subnetG, subnetPrefix, mergeByMac, includeIPv6, showHostnames, subnetExclusions, timeline, protocols]);

  // Re-evaluate display filter when graph data changes
  useEffect(() => {
    if (!dfApplied) return;
    const result = applyDisplayFilter(dfApplied, graph.nodes || [], graph.edges || []);
    if (result?.error) { setDfError(result.error); setDfResult(null); }
    else { setDfResult(result); setDfError(null); }
  }, [graph, dfApplied]);

  // ── Data loading ──────────────────────────────────────────────────

  async function loadAll() {
    const [sd, td, pd, ss, pr, ps, an, sy] = await Promise.all([
      fetchStats(), fetchTimeline(), fetchProtocols(),
      fetchSessions(), fetchPluginResults(), fetchPluginSlots(),
      fetchAnnotations(), fetchSynthetic(),
    ]);
    setStats(sd.stats);
    setTimeline(td.buckets);
    setTimeRange([0, td.buckets.length - 1]);
    setProtocols(pd.protocols);
    setPColors(pd.colors);
    setEnabledP(new Set(pd.protocols));
    setSessions(ss.sessions || []);
    setSessionTotal(ss.total ?? ss.sessions?.length ?? 0);
    setPluginResults(pr.results || {});
    setPluginSlots(ps.ui_slots || []);
    setAnnotations(an.annotations || []);
    setSynthetic(sy.synthetic || []);
    setLoaded(true);
  }

  // ── Upload handlers ───────────────────────────────────────────────

  async function handleUpload(files) {
    setLoading(true); setError(''); setLoadMsg('Uploading...');
    try {
      setLoadMsg('Parsing pcap...');
      const res = await uploadPcap(files);
      setFileName(res.file_name);
      setSourceFiles(res.source_files || [res.file_name]);
      setLoadMsg('Loading...');
      await loadAll();
      setLoading(false);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  }

  function handleDrop(e) {
    e.preventDefault();
    const files = Array.from(e.dataTransfer.files).filter(f =>
      ['.pcap', '.pcapng', '.cap'].some(ext => f.name.toLowerCase().endsWith(ext))
    );
    if (files.length) handleUpload(files);
  }

  function handleFileInput(e) {
    const files = Array.from(e.target.files || []);
    if (files.length) handleUpload(files);
    e.target.value = '';
  }

  async function handleMetadataInput(e) {
    const f = e.target.files?.[0];
    if (!f) return;
    try {
      await uploadMetadata(f);
      setGraph(prev => ({ ...prev })); // force graph re-fetch
    } catch (err) {
      console.error('Metadata upload failed:', err);
    }
    e.target.value = '';
  }

  // ── Selection handlers ────────────────────────────────────────────

  function clearSel() { setSelNodes([]); setSelEdge(null); setSelSession(null); }

  function handleGSel(type, data, shift) {
    if (type === 'node') {
      if (shift) {
        setSelNodes(p => p.includes(data) ? p.filter(n => n !== data) : [...p, data]);
        setSelEdge(null); setSelSession(null); setRPanel('detail');
      } else {
        setSelNodes([data]); setSelEdge(null); setSelSession(null); setRPanel('detail');
      }
    } else if (type === 'edge') {
      setSelEdge(data); setSelNodes([]); setSelSession(null); setRPanel('edge');
    } else {
      clearSel();
    }
  }

  function selectSession(s)     { setSelSession(s); setSelSessionSiblings([]); setSelNodes([]); setSelEdge(null); setRPanel('session'); }
  function selectSessionWithContext(s, siblings) {
    const sorted = [...(siblings || [])].sort((a, b) => (a.start_time || 0) - (b.start_time || 0));
    setSelSession(s);
    setSelSessionSiblings(sorted);
    setSelNodes([]);
    setSelEdge(null);
    setRPanel('session');
  }
  function selectNodePanel(id)  { setSelNodes([id]); setSelEdge(null); setSelSession(null); setRPanel('detail'); }
  function switchPanel(k)       { clearSel(); setRPanel(k); }

  // ── Investigation ─────────────────────────────────────────────────

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
    // Depth-1 only: the node + its direct neighbours
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

  function exitInvestigation() { setInvestigatedIp(''); setInvestigationNodes(null); }

  // ── Hide nodes ────────────────────────────────────────────────────

  function handleHideNode(nodeId) {
    setHiddenNodes(prev => { const n = new Set(prev); n.add(nodeId); return n; });
    clearSel();
  }
  function handleUnhideAll() { setHiddenNodes(new Set()); }

  // ── Annotations ───────────────────────────────────────────────────

  async function handleAddAnnotation(x, y) {
    const id = crypto.randomUUID();
    const ann = { id, x, y, label: 'Note', color: '#f0883e' };
    setAnnotations(prev => [...prev, ann]);
    try { await createAnnotation(ann); } catch (e) { console.error(e); }
  }

  async function handleUpdateAnnotation(id, updates) {
    setAnnotations(prev => prev.map(a => a.id === id ? { ...a, ...updates } : a));
    try { await updateAnnotation(id, updates); } catch (e) { console.error(e); }
  }

  async function handleDeleteAnnotation(id) {
    setAnnotations(prev => prev.filter(a => a.id !== id));
    try { await deleteAnnotation(id); } catch (e) { console.error(e); }
  }

  async function handleAddNodeAnnotation(nodeId, nodeLabel) {
    const id = crypto.randomUUID();
    const ann = { id, x: 0, y: 0, label: nodeLabel || 'Note', color: '#58a6ff', node_id: nodeId };
    setAnnotations(prev => [...prev, ann]);
    try { await createAnnotation(ann); } catch (e) { console.error(e); }
  }

  async function handleAddEdgeAnnotation(edgeId) {
    const id = crypto.randomUUID();
    const ann = { id, x: 0, y: 0, label: 'Note', color: '#bc8cff', edge_id: edgeId };
    setAnnotations(prev => [...prev, ann]);
    try { await createAnnotation(ann); } catch (e) { console.error(e); }
  }

  // ── Synthetic elements ────────────────────────────────────────────

  async function handleCreateSyntheticCluster(nodeIds) {
    if (!nodeIds || nodeIds.length < 2) return;
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];
    const memberNodes = nodes.filter(n => nodeIds.includes(n.id));
    if (!memberNodes.length) return;

    // Build cluster node — aggregates IPs, hostnames, bytes from members
    const clusterId = 'cluster:' + crypto.randomUUID().slice(0, 8);
    const labels = memberNodes.map(n =>
      n.metadata?.name || (n.hostnames?.[0]) || n.id
    );
    const label = labels.slice(0, 2).join(', ') + (labels.length > 2 ? ` +${labels.length - 2}` : '');
    const allIps = memberNodes.flatMap(n => n.ips || [n.id]);
    const totalBytes = memberNodes.reduce((s, n) => s + (n.total_bytes || 0), 0);

    const clusterNode = {
      id: clusterId, type: 'node', synthetic: true,
      label, color: '#bc8cff',
      ips: allIps, macs: [], protocols: [], hostnames: memberNodes.flatMap(n => n.hostnames || []),
      total_bytes: totalBytes, packet_count: 0,
      is_private: memberNodes.some(n => n.is_private),
      is_subnet: false, ttls_out: [], ttls_in: [],
      cluster_members: nodeIds,  // remember who's inside
    };

    // Re-route all external edges (edges where exactly one endpoint is a member)
    const memberSet = new Set(nodeIds);
    const newEdges = [];
    const seenEdgeKeys = new Set();
    edges.forEach(e => {
      const s = typeof e.source === 'object' ? e.source.id : e.source;
      const t = typeof e.target === 'object' ? e.target.id : e.target;
      const sIn = memberSet.has(s), tIn = memberSet.has(t);
      if (sIn && tIn) return; // internal edge — drop it
      if (!sIn && !tIn) return; // unrelated — keep as-is (handled by existing graph)
      // External edge — reroute to cluster node
      const newSrc = sIn ? clusterId : s;
      const newTgt = tIn ? clusterId : t;
      const key = [newSrc, newTgt, e.protocol].sort().join('|');
      if (seenEdgeKeys.has(key)) return; // deduplicate
      seenEdgeKeys.add(key);
      newEdges.push({
        ...e,
        id: clusterId + ':' + e.id,
        source: newSrc,
        target: newTgt,
        synthetic: true,
      });
    });

    // Hide member nodes and their original edges, add cluster node + rerouted edges
    setHiddenNodes(prev => new Set([...prev, ...nodeIds]));
    setSynthetic(prev => [...prev, clusterNode, ...newEdges]);
    setGraph(prev => ({
      nodes: [...(prev.nodes || []), clusterNode],
      edges: [
        ...(prev.edges || []).filter(e => {
          const s = typeof e.source === 'object' ? e.source.id : e.source;
          const t = typeof e.target === 'object' ? e.target.id : e.target;
          return !memberSet.has(s) || !memberSet.has(t); // keep external edges (they'll be hidden via hiddenNodes)
        }),
        ...newEdges,
      ],
    }));
    clearSel();
    try {
      await createSynthetic(clusterNode);
      for (const e of newEdges) await createSynthetic(e);
    } catch (err) { console.error(err); }
  }

  async function handleAddSyntheticNode(nodeData) {
    const id = crypto.randomUUID();
    const obj = {
      ...nodeData, id, type: 'node', synthetic: true,
      ips: nodeData.ip ? [nodeData.ip] : [id],
      macs: [], protocols: [], hostnames: [],
      total_bytes: 0, packet_count: 0,
      is_private: false, is_subnet: false,
      ttls_out: [], ttls_in: [],
    };
    setSynthetic(prev => [...prev, obj]);
    setGraph(prev => ({ ...prev, nodes: [...(prev.nodes || []), obj] }));
    try { await createSynthetic(obj); } catch (e) { console.error(e); }
  }

  async function handleAddSyntheticEdge(edgeData) {
    const id = crypto.randomUUID();
    const obj = {
      ...edgeData, id, type: 'edge', synthetic: true,
      total_bytes: 0, packet_count: 0,
      ports: [], tls_snis: [], tls_versions: [], tls_ciphers: [],
      tls_selected_ciphers: [], http_hosts: [], dns_queries: [],
      ja3_hashes: [], ja4_hashes: [],
    };
    setSynthetic(prev => [...prev, obj]);
    setGraph(prev => ({ ...prev, edges: [...(prev.edges || []), obj] }));
    try { await createSynthetic(obj); } catch (e) { console.error(e); }
  }

  async function handleDeleteSynthetic(id) {
    setSynthetic(prev => prev.filter(s => s.id !== id));
    setGraph(prev => ({
      nodes: (prev.nodes || []).filter(n => n.id !== id),
      edges: (prev.edges || []).filter(e => e.id !== id),
    }));
    try { await deleteSynthetic(id); } catch (e) { console.error(e); }
  }

  async function handleUpdateSyntheticNode(id, updates) {
    // Update local graph state immediately so NodeDetail re-renders
    setGraph(prev => ({
      ...prev,
      nodes: (prev.nodes || []).map(n => n.id === id ? { ...n, ...updates } : n),
    }));
    setSynthetic(prev => prev.map(s => s.id === id ? { ...s, ...updates } : s));
    try { await updateSynthetic(id, updates); } catch (e) { console.error(e); }
  }

  async function handleSaveNote(nodeId, text, existingId) {
    const id = existingId || crypto.randomUUID();
    const ann = { id, annotation_type: 'note', node_id: nodeId, label: '', text, x: 0, y: 0 };
    if (existingId) {
      setAnnotations(prev => prev.map(a => a.id === id ? { ...a, text } : a));
      try { await updateAnnotation(id, { text }); } catch (e) { console.error(e); }
    } else {
      setAnnotations(prev => [...prev, ann]);
      try { await createAnnotation(ann); } catch (e) { console.error(e); }
    }
  }

  function handleUnclusterSubnet(subnetId) {
    setSubnetExclusions(prev => new Set([...prev, subnetId]));
  }

  function toggleSubnetG() {
    setSubnetG(prev => {
      // When turning grouping OFF, clear all exclusions so re-enabling starts fresh
      if (prev) setSubnetExclusions(new Set());
      return !prev;
    });
  }

  // ── Display filter ────────────────────────────────────────────────

  function handleDfApply(expr) {
    if (!expr?.trim()) { setDfApplied(''); setDfResult(null); setDfError(null); return; }
    const result = applyDisplayFilter(expr, graph.nodes || [], graph.edges || []);
    if (result?.error) { setDfError(result.error); setDfResult(null); }
    else { setDfApplied(expr); setDfResult(result); setDfError(null); }
  }

  function handleDfClear() { setDfExpr(''); setDfApplied(''); setDfResult(null); setDfError(null); }

  // ── Panel resize ──────────────────────────────────────────────────

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

  // ── Slice URL (no state, just derives from current filter state) ──

  function getSlicePcapUrl() {
    return slicePcapUrl({
      timeStart: timeline[timeRange[0]]?.start_time,
      timeEnd:   timeline[timeRange[1]]?.end_time,
      protocols: (enabledP.size < protocols.length && enabledP.size > 0) ? Array.from(enabledP).join(',') : undefined,
      search:    search || undefined,
      includeIPv6: includeIPv6 === false ? false : undefined,
    });
  }

  // ── Return everything the layout needs ───────────────────────────

  return {
    // Lifecycle
    loaded, loading, loadMsg, error, fileName, sourceFiles,
    handleUpload, handleDrop, handleFileInput, handleMetadataInput,

    // Data
    stats, timeline, graph, sessions, sessionTotal,
    protocols, pColors, pluginResults, pluginSlots,

    // Derived
    visibleNodes, visibleEdges, timeLabel, osGuesses, availableIps,

    // Filters
    timeRange, setTimeRange,
    enabledP, setEnabledP,
    search, setSearch,
    bucketSec, setBucketSec,
    subnetG, setSubnetG, toggleSubnetG,
    labelThreshold, setLabelThreshold,
    subnetPrefix, setSubnetPrefix,
    mergeByMac, setMergeByMac,
    includeIPv6, setIncludeIPv6,
    showHostnames, setShowHostnames,


    // Display filter
    dfExpr, setDfExpr,
    dfApplied, dfError, dfResult,
    handleDfApply, handleDfClear,

    // Annotations
    annotations,
    handleAddAnnotation, handleUpdateAnnotation, handleDeleteAnnotation,
    handleAddNodeAnnotation, handleAddEdgeAnnotation,

    // Synthetic
    handleAddSyntheticNode, handleAddSyntheticEdge, handleDeleteSynthetic,
    handleUpdateSyntheticNode, handleSaveNote, handleCreateSyntheticCluster,
    handleUnclusterSubnet,

    // Selection
    selNodes, selEdge, selSession, selSessionSiblings, rPanel,
    handleGSel, selectSession, selectSessionWithContext, selectNodePanel, switchPanel, clearSel,
    handleInvestigate, handleInvestigateNeighbours, exitInvestigation,

    // Investigation & hidden
    investigatedIp, investigationNodes,
    hiddenNodes, handleHideNode, handleUnhideAll,
    seqAckSessionId, setSeqAckSessionId,

    // Panel
    panelWidth, setPanelWidth, handlePanelDragStart,
    getSlicePcapUrl,

    // Graph setter (used by synthetic add)
    setGraph,
  };
}
