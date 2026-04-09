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

import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import {
  fetchStatus, fetchStats, slicePcapUrl,
  fetchTimeline, fetchProtocols, fetchSessions,
  fetchPluginResults, fetchPluginSlots, fetchGraph,
  uploadPcap, uploadMetadata,
  fetchAnnotations, createAnnotation, updateAnnotation, deleteAnnotation,
  fetchSynthetic, createSynthetic, updateSynthetic, deleteSynthetic,
  fetchPaths, fetchAlerts,
} from '../api';
import { fTtime } from '../utils';
import { applyDisplayFilter } from '../displayFilter';
import { applyClusterView } from '../clusterView';
import { matchSessionToEdge } from '../sessionMatch';
import { useAnimationMode } from './useAnimationMode';
import useEvents from './useEvents';

const SESSIONS_FETCH_LIMIT = 1000;
const TIME_RANGE_DEBOUNCE_MS = 300;

export function useCapture() {

  // ── Animation mode (decoupled sub-hook) ─────────────────────────
  const anim = useAnimationMode();

  // ── Events: researcher-flagged nodes/edges/sessions (v0.21.0) ────
  const evs = useEvents();
  // Modal state — { entity, entity_type } or null
  const [flaggingTarget, setFlaggingTarget] = useState(null);

  function openFlagModal(entity_type, entity) {
    if (!entity || !entity_type) return;
    setFlaggingTarget({ entity, entity_type });
  }
  function closeFlagModal() { setFlaggingTarget(null); }

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
  const [rawGraph, setRawGraph]      = useState({ nodes: [], edges: [], clusters: null });
  const [sessions, setSessions]     = useState([]);
  const [fullSessions, setFullSessions] = useState([]); // full-capture snapshot, never time-filtered
  const [sessionTotal, setSessionTotal] = useState(0);
  const [protocols, setProtocols]   = useState([]);
  const [pColors, setPColors]       = useState({});
  const [pluginResults, setPluginResults] = useState({});
  const [pluginSlots, setPluginSlots]     = useState([]);

  // ── Filters ──────────────────────────────────────────────────────
  const [timeRange, setTimeRange]   = useState([0, 0]);
  const [debouncedTR, setDebouncedTR] = useState([0, 0]);
  const trTimerRef = useRef(null);
  const setTimeRangeOuter = useCallback((v) => {
    setTimeRange(v);
    clearTimeout(trTimerRef.current);
    trTimerRef.current = setTimeout(() => setDebouncedTR(v), TIME_RANGE_DEBOUNCE_MS);
  }, []);
  const [enabledP, setEnabledP]     = useState(new Set());
  const [search, setSearch]         = useState('');
  const [searchResult, setSearchResult] = useState(null); // {nodes: Set, edges: Set, matchedNodes, matchedEdges} or null
  const [bucketSec, setBucketSec]   = useState(15);
  const [subnetG, setSubnetG]       = useState(false);
  const [labelThreshold, setLabelThreshold] = useState(0); // hide labels below this bytes value (0 = show all)
  const [graphWeightMode, setGraphWeightMode] = useState('bytes'); // 'bytes' | 'packets' — node radius driver
  const [edgeSizeMode, setEdgeSizeMode] = useState('bytes');       // 'bytes' | 'packets' | 'sessions' — edge thickness driver
  const [nodeColorMode, setNodeColorMode] = useState('address');   // 'address' | 'os' | 'protocol' | 'volume' | 'custom'
  const [edgeColorMode, setEdgeColorMode] = useState('protocol');  // 'protocol' | 'volume' | 'sessions' | 'custom'
  const [nodeColorRules, setNodeColorRules] = useState([]);        // [{color, text}] — custom node coloring rules
  const [edgeColorRules, setEdgeColorRules] = useState([]);        // [{color, text}] — custom edge coloring rules

  const [subnetPrefix, setSubnetPrefix] = useState(24);
  const [debouncedSubnetPrefix, setDebouncedSubnetPrefix] = useState(24);
  const spTimerRef = useRef(null);
  const setSubnetPrefixOuter = useCallback((v) => {
    setSubnetPrefix(v);
    clearTimeout(spTimerRef.current);
    spTimerRef.current = setTimeout(() => setDebouncedSubnetPrefix(v), 400);
  }, []);
  const [mergeByMac, setMergeByMac] = useState(false);
  const [includeIPv6, setIncludeIPv6] = useState(true);
  const [showHostnames, setShowHostnames] = useState(true);
  const [excludeBroadcasts, setExcludeBroadcasts] = useState(false);
  const [subnetExclusions, setSubnetExclusions] = useState(new Set());
  const [clusterAlgo, setClusterAlgo] = useState('');  // '' | 'louvain' | 'kcore' | 'hub_spoke' | 'shared_neighbor'
  const [clusterResolution, setClusterResolution] = useState(1.0);
  const [clusterNames, setClusterNames] = useState({});  // cluster_id -> custom name
  const [clusterExclusions, setClusterExclusions] = useState(new Set());  // cluster_ids left expanded
  const [manualClusters, setManualClusters] = useState({});  // node_id -> cluster_id (user-created groups)
  // Clear custom names and exclusions when algorithm changes
  const prevAlgoRef = useRef(clusterAlgo);
  useEffect(() => {
    if (clusterAlgo !== prevAlgoRef.current) {
      setClusterNames({});
      setClusterExclusions(new Set());
      setManualClusters({});
      prevAlgoRef.current = clusterAlgo;
    }
  }, [clusterAlgo]);

  // ── Derived graph (applies cluster view transform) ──────────────
  // rawGraph holds the real backend data (never mutated).
  // `graph` is what components see — clustered view when active, raw otherwise.
  // Toggling clustering off is instant (no API call) because raw data is preserved.
  const graph = useMemo(() => {
    const algoClusters = (clusterAlgo && rawGraph.clusters) ? rawGraph.clusters : {};
    const hasManual = Object.keys(manualClusters).length > 0;
    const hasAlgo = Object.keys(algoClusters).length > 0;
    if (!hasAlgo && !hasManual) return rawGraph;
    // Merge: manual clusters override algo assignments for the same node
    const merged = hasManual ? { ...algoClusters, ...manualClusters } : algoClusters;
    const view = applyClusterView(rawGraph.nodes || [], rawGraph.edges || [], merged, clusterExclusions);
    return { ...rawGraph, nodes: view.nodes, edges: view.edges };
  }, [rawGraph, clusterAlgo, clusterExclusions, manualClusters]);

  // Expose setGraph for synthetic node/edge additions — these mutate rawGraph
  const setGraph = useCallback((updater) => {
    if (typeof updater === 'function') {
      setRawGraph(prev => updater(prev));
    } else {
      setRawGraph(updater);
    }
  }, []);

  // ── Display filter ────────────────────────────────────────────────
  const [dfExpr, setDfExpr]       = useState('');
  const [dfApplied, setDfApplied] = useState('');
  const [dfError, setDfError]     = useState(null);
  const [dfResult, setDfResult]   = useState(null);

  // ── Annotations & synthetic ───────────────────────────────────────
  const [annotations, setAnnotations] = useState([]);
  const [synthetic, setSynthetic]     = useState([]);
  const [alerts, setAlerts]           = useState({ alerts: [], summary: {} });

  // ── Selection & UI routing ────────────────────────────────────────
  const [selNodes, setSelNodes]   = useState([]);
  const [selEdge, setSelEdge]     = useState(null);
  const [selSession, setSelSession] = useState(null);
  const [selSessionSiblings, setSelSessionSiblings] = useState([]);  // sorted sibling sessions from edge
  const [rPanel, setRPanel]       = useState('stats');

  // ── Navigation history (back/forward) ──────────────────────────
  const navHistoryRef = useRef([]);   // array of snapshots
  const navIndexRef = useRef(-1);     // current position in history
  const navRestoringRef = useRef(false); // flag to prevent pushing while restoring

  // Refs that always hold the latest state values (for snapshot accuracy)
  const latestRef = useRef({});
  latestRef.current = { selNodes, selEdge, selSession, selSessionSiblings, rPanel, search };

  function _navSnapshot() {
    const s = latestRef.current;
    return { selNodes: [...s.selNodes], selEdge: s.selEdge, selSession: s.selSession, selSessionSiblings: [...s.selSessionSiblings], rPanel: s.rPanel, search: s.search };
  }
  function _navPush() {
    if (navRestoringRef.current) return;
    const snap = _navSnapshot();
    // Trim forward history if we navigated back then went somewhere new
    navHistoryRef.current = navHistoryRef.current.slice(0, navIndexRef.current + 1);
    navHistoryRef.current.push(snap);
    // Cap at 50 entries
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
    // Clear restoring flag after React processes the state updates
    setTimeout(() => { navRestoringRef.current = false; }, 0);
  }
  function navBack() {
    if (navIndexRef.current <= 0) return;
    // Save current state as the "forward" entry if we're at the end
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
  // ── Pathfinding ────────────────────────────────────────────────────
  const [pathfindSource, setPathfindSource]       = useState(null);  // node ID awaiting target pick
  const [pathfindResult, setPathfindResult]       = useState(null);  // aggregated {hop_layers, edges, nodes, ...}
  const [pathfindLoading, setPathfindLoading]     = useState(false);
  // Clear stale pathfind results when graph data changes (time range, filters, etc.)
  const prevRawGraphRef = useRef(rawGraph);
  useEffect(() => {
    if (rawGraph !== prevRawGraphRef.current) {
      prevRawGraphRef.current = rawGraph;
      if (pathfindResult) {
        setPathfindResult(null);
        setPathfindSource(null);
        setInvestigatedIp('');
        setInvestigationNodes(null);
      }
    }
  }, [rawGraph]); // eslint-disable-line react-hooks/exhaustive-deps
  const [seqAckSessionId, setSeqAckSessionId]     = useState('');

  // Per-session collapse state memory: Map<sessionId, Set<title>>
  // Persists which sections the user opened, so navigating back restores them.
  const collapseStatesRef = useRef(new Map());

  // ── Panel resize ─────────────────────────────────────────────────
  const [panelWidth, setPanelWidth] = useState(330);
  const panelDragRef = useRef(null);

  // Clear selection when search text changes — prevents old selection
  // persisting when user searches something new
  const prevSearchRef = useRef('');
  useEffect(() => {
    if (prevSearchRef.current && prevSearchRef.current !== search) {
      setSelNodes([]); setSelEdge(null); setSelSession(null);
    }
    prevSearchRef.current = search;
  }, [search]);

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

  // Escape to deselect + clear search
  useEffect(() => {
    const h = e => { if (e.key === 'Escape') clearAll(); };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, []);

  // Re-fetch timeline when bucket size changes
  useEffect(() => {
    if (!loaded) return;
    fetchTimeline(bucketSec).then(d => {
      setTimeline(d.buckets);
      const full = [0, d.buckets.length - 1];
      setTimeRange(full);
      setDebouncedTR(full);
    }).catch(() => {});
  }, [bucketSec, loaded]);

  // Re-fetch sessions when time range changes (debounced)
  useEffect(() => {
    if (!loaded || !timeline.length) return;
    const ts = timeline[debouncedTR[0]]?.start_time;
    const te = timeline[debouncedTR[1]]?.end_time;
    fetchSessions(SESSIONS_FETCH_LIMIT, '', ts != null && te != null ? { timeStart: ts, timeEnd: te } : {})
      .then(d => { setSessions(d.sessions || []); setSessionTotal(d.total ?? d.sessions?.length ?? 0); })
      .catch(() => {});
  }, [loaded, debouncedTR, timeline]);

  // Re-fetch stats when time range changes (debounced)
  useEffect(() => {
    if (!loaded || !timeline.length) return;
    const ts = timeline[debouncedTR[0]]?.start_time;
    const te = timeline[debouncedTR[1]]?.end_time;
    fetchStats(ts != null && te != null ? { timeStart: ts, timeEnd: te } : {})
      .then(d => setStats(d.stats || {}))
      .catch(() => {});
  }, [loaded, debouncedTR, timeline]);

  // Stable ref: total count of composite protocol keys — updated whenever stats/protocols change.
  // Used inside the graph fetch effect to determine if all protocols are enabled (no filter needed).
  // Kept as a ref so updating it does NOT trigger a graph refetch.
  const allProtocolKeysCountRef = useRef(0);
  const fullGraphRef = useRef(null); // full-capture graph (nodes + edges), set once on first fetch
  useEffect(() => {
    const sp = stats?.protocols || {};
    const _nonIp = new Set(['ARP', 'OTHER']);
    let count = 0;
    for (const pName of protocols) {
      if (!pName || !pName.trim()) continue;
      const info = sp[pName] || {};
      const transport = info.transport || pName;
      const v4 = info.ipv4 || 0;
      const v6 = info.ipv6 || 0;
      const total = info.packets || 0;
      if (_nonIp.has(transport)) {
        count += 1;
      } else {
        if (v4 > 0 || (v6 === 0 && total > 0)) count += 1;
        if (v6 > 0) count += 1;
      }
    }
    allProtocolKeysCountRef.current = count;
  }, [stats, protocols]);

  // Re-fetch graph when any filter changes (debounced)
  useEffect(() => {
    if (!loaded || !timeline.length) return;
    const ts = timeline[debouncedTR[0]]?.start_time;
    const te = timeline[debouncedTR[1]]?.end_time;
    const params = {};
    if (ts != null) params.timeStart = ts;
    if (te != null) params.timeEnd = te;
    // Send composite protocol filter keys (e.g. "4/TCP/HTTPS,6/UDP/DNS")
    // Only send filter if not all keys are enabled — compare against stable ref count
    if (enabledP.size > 0 && enabledP.size < allProtocolKeysCountRef.current)
      params.protocolFilters = Array.from(enabledP).join(',');
    if (subnetG) { params.subnetGrouping = true; params.subnetPrefix = debouncedSubnetPrefix; }
    if (mergeByMac)   params.mergeByMac = true;
    if (!includeIPv6) params.includeIPv6 = false;
    if (!showHostnames) params.showHostnames = false;
    if (excludeBroadcasts) params.excludeBroadcasts = true;
    if (subnetExclusions.size > 0) params.subnetExclusions = subnetExclusions;
    if (clusterAlgo) {
      params.clusterAlgorithm = clusterAlgo;
      if (clusterAlgo === 'louvain') params.clusterResolution = clusterResolution;
    }

    const ctrl = new AbortController();
    fetchGraph(params, ctrl.signal).then(d => {
      // If user explicitly selected no protocols (and protocols are loaded), show no edges
      const noneSelected = enabledP.size === 0 && allProtocolKeysCountRef.current > 0;
      setRawGraph(noneSelected ? { ...d, edges: [] } : d);
      if (!fullGraphRef.current) fullGraphRef.current = { nodes: d.nodes || [], edges: d.edges || [] };
    }).catch(e => {
      if (e.name !== 'AbortError') console.error(e);
    });
    return () => ctrl.abort();
  }, [loaded, debouncedTR, enabledP, subnetG, debouncedSubnetPrefix, mergeByMac, includeIPv6, showHostnames, excludeBroadcasts, subnetExclusions, clusterAlgo, clusterResolution, timeline, protocols]);

  // Re-evaluate display filter when graph data changes
  useEffect(() => {
    if (!dfApplied) return;
    const result = applyDisplayFilter(dfApplied, graph.nodes || [], graph.edges || []);
    if (result?.error) { setDfError(result.error); setDfResult(null); }
    else { setDfResult(result); setDfError(null); }
  }, [graph, dfApplied]);

  // Client-side search: match query against all node/edge/session fields, produce Sets for dimming + details for dropdown
  useEffect(() => {
    if (!search) { setSearchResult(null); return; }
    const q = search.toLowerCase();
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];

    const matchNode = n => {
      for (const ip of (n.ips || [])) { if (ip.toLowerCase().includes(q)) return 'ip'; }
      for (const mac of (n.macs || [])) { if (mac.toLowerCase().includes(q)) return 'mac'; }
      for (const v of (n.mac_vendors || [])) { if (v && v.toLowerCase().includes(q)) return 'vendor'; }
      for (const h of (n.hostnames || [])) { if (h.toLowerCase().includes(q)) return 'hostname'; }
      if (n.os_guess && n.os_guess.toLowerCase().includes(q)) return 'os';
      if (n.id && n.id.toLowerCase().includes(q)) return 'id';
      if (n.metadata) {
        for (const [mk, mv] of Object.entries(n.metadata)) { if (mv && String(mv).toLowerCase().includes(q)) return 'metadata: ' + mk; }
      }
      return null;
    };

    // Skip keys that are not useful for text search on edges
    const _SKIP_EDGE_KEYS = new Set([
      'id', 'source', 'target', 'protocol', 'type', 'synthetic',
      'total_bytes', 'packet_count', 'ports',
      'bytes_to_source', 'bytes_to_target', 'packets_to_source', 'packets_to_target',
    ]);
    // Protocol-name keyword hints — lets user type "tls", "dns", "http" to find edges
    // with those field groups even when no individual value matched.
    const _PROTO_HINTS = [
      { keys: ['tls_snis', 'tls_versions', 'tls_ciphers', 'tls_selected_ciphers'], keyword: 'tls' },
      { keys: ['tls_snis'], keyword: 'sni' },
      { keys: ['tls_ciphers', 'tls_selected_ciphers'], keyword: 'cipher' },
      { keys: ['http_hosts'], keyword: 'http' },
      { keys: ['dns_queries'], keyword: 'dns' },
      { keys: ['ja3_hashes'], keyword: 'ja3' },
      { keys: ['ja4_hashes'], keyword: 'ja4' },
    ];
    const matchEdge = e => {
      if (e.protocol && e.protocol.toLowerCase().includes(q)) return 'protocol';
      // Generic: iterate all string/array properties on the edge object
      for (const [key, val] of Object.entries(e)) {
        if (_SKIP_EDGE_KEYS.has(key)) continue;
        if (typeof val === 'string' && val.toLowerCase().includes(q)) return key;
        if (Array.isArray(val)) {
          for (const item of val) {
            if (typeof item === 'string' && item.toLowerCase().includes(q)) return key;
          }
        }
      }
      const src = e.source?.id || e.source || '';
      const tgt = e.target?.id || e.target || '';
      if (src.toLowerCase().includes(q) || tgt.toLowerCase().includes(q)) return 'endpoint';
      // Protocol-name keyword hints
      for (const hint of _PROTO_HINTS) {
        if (hint.keyword.includes(q) && hint.keys.some(k => e[k]?.length)) return `has ${hint.keyword}`;
      }
      if (e.protocol_conflict && 'conflict'.includes(q)) return 'protocol conflict';
      return null;
    };

    // Generic session field search — matches string/array values on session objects
    // so that fields like user_agents, URIs, SSH banners, Kerberos principals, LDAP DNs
    // are all searchable without hardcoding each field name.
    const _SKIP_SESSION_KEYS = new Set([
      'id', 'session_key', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
      'initiator_ip', 'responder_ip', 'initiator_port', 'responder_port',
      'packet_count', 'total_bytes', 'duration', 'start_time', 'end_time',
      'bytes_to_initiator', 'bytes_to_responder', 'packets_to_initiator',
      'packets_to_responder', 'ip_version', 'transport',
    ]);
    const matchSession = sess => {
      for (const [key, val] of Object.entries(sess)) {
        if (_SKIP_SESSION_KEYS.has(key)) continue;
        if (typeof val === 'string' && val.toLowerCase().includes(q)) return key;
        if (Array.isArray(val)) {
          for (const item of val) {
            if (typeof item === 'string' && item.toLowerCase().includes(q)) return key;
            if (item && typeof item === 'object') {
              for (const v of Object.values(item)) {
                if (typeof v === 'string' && v.toLowerCase().includes(q)) return key;
              }
            }
          }
        }
      }
      return null;
    };

    const directNodes = [];
    const directEdges = [];
    const directNodeIds = new Set();
    const directEdgeIds = new Set();
    for (const n of nodes) {
      const reason = matchNode(n);
      if (reason) { directNodes.push({ node: n, reason }); directNodeIds.add(n.id); }
    }
    for (const e of edges) {
      const reason = matchEdge(e);
      if (reason) { directEdges.push({ edge: e, reason }); directEdgeIds.add(e.id); }
    }

    // Search sessions and map matches back to edges + nodes
    if (sessions.length > 0) {
      for (const sess of sessions) {
        if (matchSession(sess)) {
          // Find matching edge(s) for this session using canonical matcher
          for (const e of edges) {
            if (directEdgeIds.has(e.id)) continue;
            const eSrc = e.source?.id || e.source;
            const eTgt = e.target?.id || e.target;
            if (matchSessionToEdge(sess, eSrc, eTgt, e.protocol)) {
              directEdges.push({ edge: e, reason: 'session match' });
              directEdgeIds.add(e.id);
              if (!directNodeIds.has(eSrc)) { directNodeIds.add(eSrc); }
              if (!directNodeIds.has(eTgt)) { directNodeIds.add(eTgt); }
            }
          }
        }
      }
    }

    const matchedNodeIds = new Set(directNodeIds);
    const matchedEdgeIds = new Set(directEdgeIds);
    for (const e of edges) {
      const src = e.source?.id || e.source;
      const tgt = e.target?.id || e.target;
      if (directNodeIds.has(src) || directNodeIds.has(tgt)) {
        matchedEdgeIds.add(e.id);
      }
    }

    setSearchResult({
      nodes: matchedNodeIds, edges: matchedEdgeIds,
      matchedNodes: directNodes.slice(0, 20),
      matchedEdges: directEdges.slice(0, 20),
      totalNodes: directNodes.length,
      totalEdges: directEdges.length,
    });
  }, [search, graph, sessions]);

  // ── Data loading ──────────────────────────────────────────────────

  async function loadAll() {
    // Reset scope pills to SCOPED on every fresh capture load
    try {
      localStorage.removeItem('swifteye_scope_node');
      localStorage.removeItem('swifteye_scope_edge');
      Object.keys(localStorage)
        .filter(k => k.startsWith('swifteye_scope_slot_'))
        .forEach(k => localStorage.removeItem(k));
    } catch {}

    const [sd, td, pd, ss, pr, ps, an, sy, al] = await Promise.all([
      fetchStats(), fetchTimeline(), fetchProtocols(),
      fetchSessions(), fetchPluginResults(), fetchPluginSlots(),
      fetchAnnotations(), fetchSynthetic(), fetchAlerts(),
    ]);
    setStats(sd.stats);
    setTimeline(td.buckets);
    const fullRange = [0, td.buckets.length - 1];
    setTimeRange(fullRange);
    setDebouncedTR(fullRange);
    setProtocols(pd.protocols);
    setPColors(pd.colors);
    // Build composite keys "ipv/transport/protocol" for the protocol tree
    const sp = sd.stats?.protocols || {};
    const initKeys = [];
    const nonIpTransports = new Set(['ARP', 'OTHER']);
    for (const pName of pd.protocols) {
      if (!pName || !pName.trim()) continue;
      const info = sp[pName] || {};
      const transport = info.transport || pName;
      const v4 = info.ipv4 || 0;
      const v6 = info.ipv6 || 0;
      const total = info.packets || 0;
      if (nonIpTransports.has(transport)) {
        initKeys.push(`0/${transport}/${pName}`);
      } else {
        if (v4 > 0 || (v6 === 0 && total > 0)) initKeys.push(`4/${transport}/${pName}`);
        if (v6 > 0) initKeys.push(`6/${transport}/${pName}`);
      }
    }
    setEnabledP(new Set(initKeys));
    setSessions(ss.sessions || []);
    setFullSessions(ss.sessions || []);
    setSessionTotal(ss.total ?? ss.sessions?.length ?? 0);
    setPluginResults(pr.results || {});
    setPluginSlots(ps.ui_slots || []);
    setAnnotations(an.annotations || []);
    setSynthetic(sy.synthetic || []);
    setAlerts(al || { alerts: [], summary: {} });
    setLoaded(true);
  }

  // ── Upload handlers ───────────────────────────────────────────────

  async function handleUpload(files) {
    setLoading(true); setError(''); setLoadMsg('Uploading...');
    try {
      setLoadMsg('Parsing capture data...');
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
      ['.pcap', '.pcapng', '.cap', '.log', '.csv'].some(ext => f.name.toLowerCase().endsWith(ext))
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
  function clearAll() { _navPush(); clearSel(); setSearch(''); } // escape + canvas bg click

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
      // Canvas background click — clearAll handles its own _navPush
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

  // ── Hide nodes ────────────────────────────────────────────────────

  function handleHideNode(nodeId) {
    setHiddenNodes(prev => {
      if (prev.has(nodeId)) return prev; // no-op guard: same identity
      const n = new Set(prev); n.add(nodeId); return n;
    });
    clearSel();
  }
  function handleUnhideAll() {
    setHiddenNodes(prev => prev.size === 0 ? prev : new Set()); // no-op guard
  }

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

  function handleCreateManualCluster(nodeIds) {
    if (!nodeIds || nodeIds.length < 2) return;
    // Find the next available cluster_id (above any existing algo or manual cluster)
    const algoClusters = (clusterAlgo && rawGraph.clusters) ? rawGraph.clusters : {};
    const allIds = [...Object.values(algoClusters), ...Object.values(manualClusters)];
    const nextId = allIds.length > 0 ? Math.max(...allIds) + 1 : 0;
    // Assign all selected nodes to this new cluster
    setManualClusters(prev => {
      const updated = { ...prev };
      for (const id of nodeIds) updated[id] = nextId;
      return updated;
    });
    clearSel();
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

  async function handleSaveNote(targetId, text, existingId, targetType = 'node_id') {
    const id = existingId || crypto.randomUUID();
    const ann = { id, annotation_type: 'note', [targetType]: targetId, label: '', text, x: 0, y: 0 };
    if (existingId) {
      setAnnotations(prev => prev.map(a => a.id === id ? { ...a, text } : a));
      try { await updateAnnotation(id, { text }); } catch (e) { console.error(e); }
    } else {
      setAnnotations(prev => [...prev, ann]);
      try { await createAnnotation(ann); } catch (e) { console.error(e); }
    }
  }

  function handleUnclusterSubnet(subnetId) {
    setSubnetExclusions(prev => {
      if (prev.has(subnetId)) return prev; // no-op guard
      return new Set([...prev, subnetId]);
    });
  }

  function handleExpandCluster(clusterId) {
    setClusterExclusions(prev => {
      if (prev.has(clusterId)) return prev; // no-op guard
      return new Set([...prev, clusterId]);
    });
  }

  function handleCollapseCluster(clusterId) {
    setClusterExclusions(prev => {
      if (!prev.has(clusterId)) return prev; // no-op guard
      const s = new Set(prev); s.delete(clusterId); return s;
    });
  }

  function toggleSubnetG() {
    setSubnetG(prev => {
      // When turning grouping OFF, clear all exclusions so re-enabling starts fresh
      if (prev) setSubnetExclusions(prev => prev.size === 0 ? prev : new Set());
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
    stats, timeline, graph, rawGraph, sessions, sessionTotal,
    protocols, pColors, pluginResults, pluginSlots,

    // Derived
    visibleNodes, visibleEdges, timeLabel, osGuesses, availableIps,

    // Filters
    timeRange, setTimeRange: setTimeRangeOuter,
    enabledP, setEnabledP,
    search, setSearch, searchResult,
    collapseStatesRef,
    bucketSec, setBucketSec,
    subnetG, setSubnetG, toggleSubnetG,
    labelThreshold, setLabelThreshold,
    graphWeightMode, setGraphWeightMode,
    edgeSizeMode, setEdgeSizeMode,
    nodeColorMode, setNodeColorMode,
    edgeColorMode, setEdgeColorMode,
    nodeColorRules, setNodeColorRules,
    edgeColorRules, setEdgeColorRules,
    subnetPrefix, setSubnetPrefix: setSubnetPrefixOuter,
    mergeByMac, setMergeByMac,
    includeIPv6, setIncludeIPv6,
    showHostnames, setShowHostnames,
    excludeBroadcasts, setExcludeBroadcasts,
    clusterAlgo, setClusterAlgo,
    clusterResolution, setClusterResolution,
    clusterNames, renameCluster: (id, name) => setClusterNames(prev => ({ ...prev, [id]: name })),
    clusterExclusions, handleExpandCluster, handleCollapseCluster,

    // Full-capture snapshots for ALL scope mode (never time-filtered)
    fullSessions, fullGraphRef,

    // Protocol key count ref (composite keys — matches enabledP format)
    allProtocolKeysCountRef,

    // Display filter
    dfExpr, setDfExpr,
    dfApplied, dfError, dfResult,
    handleDfApply, handleDfClear,

    // Annotations
    annotations,
    handleAddAnnotation, handleUpdateAnnotation, handleDeleteAnnotation,
    handleAddNodeAnnotation, handleAddEdgeAnnotation,

    // Alerts
    alerts, setAlerts,

    // Synthetic
    handleAddSyntheticNode, handleAddSyntheticEdge, handleDeleteSynthetic,
    handleUpdateSyntheticNode, handleSaveNote, handleCreateManualCluster,
    handleUnclusterSubnet,

    // Selection
    selNodes, selEdge, selSession, selSessionSiblings, rPanel,
    handleGSel, selectSession, selectSessionWithContext, selectNodePanel, switchPanel, clearSel, clearAll,
    navBack, navForward, canGoBack, canGoForward,
    handleInvestigate, handleInvestigateNeighbours, exitInvestigation,

    // Investigation & hidden
    investigatedIp, investigationNodes,
    hiddenNodes, handleHideNode, handleUnhideAll,

    // Pathfinding
    pathfindSource, startPathfind, cancelPathfind, executePathfind,
    pathfindResult, pathfindLoading, runPathfindFromPanel,
    seqAckSessionId, setSeqAckSessionId,

    // Panel
    panelWidth, setPanelWidth, handlePanelDragStart,
    getSlicePcapUrl,

    // Graph setter (used by synthetic add)
    setGraph,

    // Animation mode (decoupled sub-hook)
    ...anim,

    // Events (v0.21.0) — researcher-flagged nodes/edges/sessions
    events: evs.events,
    timelineEdges: evs.timelineEdges,
    suggestedEdges: evs.suggestedEdges,
    addEvent: evs.addEvent,
    updateEvent: evs.updateEvent,
    removeEvent: evs.removeEvent,
    placeEvent: evs.placeEvent,
    unplaceEvent: evs.unplaceEvent,
    addTimelineEdge: evs.addTimelineEdge,
    updateTimelineEdge: evs.updateTimelineEdge,
    removeTimelineEdge: evs.removeTimelineEdge,
    acceptSuggestion: evs.acceptSuggestion,
    nodeEventSeverity: evs.nodeEventSeverity,
    edgeEventSeverity: evs.edgeEventSeverity,
    getEventsForEntity: evs.getEventsForEntity,
    flaggingTarget, openFlagModal, closeFlagModal,
  };
}
