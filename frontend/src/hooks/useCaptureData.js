/**
 * useCaptureData — server-fetched data state, all refetch effects, derived
 * graph view, display filter, and client-side search.
 *
 * Extracted from useCapture as part of the decomposition (v0.25.0).
 * Highest-risk slice: owns many effects, ref guards, and abort controllers.
 *
 * Cross-slice params:
 *   - loaded (from coordinator)
 *   - filters (return object from useCaptureFilters)
 *   - setAlerts (from annotations slice)
 *   - selCallbacksRef.current.clearPathfindState (from selection slice, via ref)
 */

import { useState, useRef, useEffect, useMemo, useCallback } from 'react';
import {
  fetchStats, fetchTimeline, fetchSessions, fetchGraph,
  fetchAlerts, slicePcapUrl,
} from '../api';
import { fTtime } from '../utils';
import { applyDisplayFilter } from '../displayFilter';
import { applyClusterView } from '../clusterView';
import { matchSessionToEdge } from '../sessionMatch';

const SESSIONS_FETCH_LIMIT = 1000;

export function useCaptureData({ loaded, filters, setAlerts, selCallbacksRef }) {

  // Destructure filter values used as effect/memo deps
  const {
    debouncedTR, enabledP, search, bucketSec,
    subnetG, debouncedSubnetPrefix, mergeByMac, includeIPv6, showHostnames,
    excludeBroadcasts, subnetExclusions, clusterAlgo, clusterResolution,
    clusterExclusions, manualClusters, resetTimeRange,
  } = filters;

  // ── Server data state ────────────────────────────────────────────

  const [stats, setStats]               = useState(null);
  const [timeline, setTimeline]         = useState([]);
  const [rawGraph, setRawGraph]         = useState({ nodes: [], edges: [], clusters: null });
  const [sessions, setSessions]         = useState([]);
  const [fullSessions, setFullSessions] = useState([]);
  const [sessionTotal, setSessionTotal] = useState(0);
  const [protocols, setProtocols]       = useState([]);
  const [pColors, setPColors]           = useState({});
  const [pluginResults, setPluginResults] = useState({});
  const [pluginSlots, setPluginSlots]     = useState([]);

  // ── setGraph wrapper (for synthetic mutations) ───────────────────

  const setGraph = useCallback((updater) => {
    if (typeof updater === 'function') {
      setRawGraph(prev => updater(prev));
    } else {
      setRawGraph(updater);
    }
  }, []);

  // ── Derived graph (applies cluster view transform) ───────────────

  const graph = useMemo(() => {
    const algoClusters = (clusterAlgo && rawGraph.clusters) ? rawGraph.clusters : {};
    const hasManual = Object.keys(manualClusters).length > 0;
    const hasAlgo = Object.keys(algoClusters).length > 0;
    if (!hasAlgo && !hasManual) return rawGraph;
    const merged = hasManual ? { ...algoClusters, ...manualClusters } : algoClusters;
    const view = applyClusterView(rawGraph.nodes || [], rawGraph.edges || [], merged, clusterExclusions);
    return { ...rawGraph, nodes: view.nodes, edges: view.edges };
  }, [rawGraph, clusterAlgo, clusterExclusions, manualClusters]);

  // ── Display filter ───────────────────────────────────────────────

  const [dfExpr, setDfExpr]       = useState('');
  const [dfApplied, setDfApplied] = useState('');
  const [dfError, setDfError]     = useState(null);
  const [dfResult, setDfResult]   = useState(null);

  // ── Search result ────────────────────────────────────────────────

  const [searchResult, setSearchResult] = useState(null);

  // ── Refs ─────────────────────────────────────────────────────────

  const allProtocolKeysCountRef = useRef(0);
  const fullGraphRef = useRef(null);
  const prevRawGraphRef = useRef(rawGraph);

  // ── Derived memos ────────────────────────────────────────────────

  const timeLabel = useMemo(() => {
    if (!timeline.length) return '';
    const s = timeline[filters.timeRange[0]], e = timeline[filters.timeRange[1]];
    return s && e ? fTtime(s.start_time) + ' — ' + fTtime(e.end_time) : '';
  }, [timeline, filters.timeRange]);

  const osGuesses = useMemo(
    () => [...new Set((graph.nodes || []).map(n => n.os_guess).filter(Boolean))].sort(),
    [graph.nodes]
  );

  const availableIps = useMemo(
    () => [...new Set((graph.nodes || []).flatMap(n => n.ips || [n.id]).filter(ip => ip && !ip.includes('/')))].sort(),
    [graph.nodes]
  );

  // ── Init from full-capture load ──────────────────────────────────

  const initFromLoad = useCallback(({
    stats: s, timeline: t, protocols: p, pColors: pc,
    sessions: ss, fullSessions: fs, sessionTotal: st,
    pluginResults: pr, pluginSlots: ps,
  }) => {
    setStats(s);
    setTimeline(t);
    setProtocols(p);
    setPColors(pc);
    setSessions(ss);
    setFullSessions(fs);
    setSessionTotal(st);
    setPluginResults(pr);
    setPluginSlots(ps);
  }, []);

  // ── Effects ──────────────────────────────────────────────────────

  // E3: re-fetch timeline when bucket size changes
  useEffect(() => {
    if (!loaded) return;
    fetchTimeline(bucketSec).then(d => {
      setTimeline(d.buckets);
      resetTimeRange(d.buckets.length);
    }).catch(() => {});
  }, [bucketSec, loaded, resetTimeRange]);

  // E4: re-fetch sessions when time range changes (debounced)
  useEffect(() => {
    if (!loaded || !timeline.length) return;
    const ts = timeline[debouncedTR[0]]?.start_time;
    const te = timeline[debouncedTR[1]]?.end_time;
    fetchSessions(SESSIONS_FETCH_LIMIT, '', ts != null && te != null ? { timeStart: ts, timeEnd: te } : {})
      .then(d => { setSessions(d.sessions || []); setSessionTotal(d.total ?? d.sessions?.length ?? 0); })
      .catch(() => {});
  }, [loaded, debouncedTR, timeline]);

  // E5: re-fetch stats when time range changes (debounced)
  useEffect(() => {
    if (!loaded || !timeline.length) return;
    const ts = timeline[debouncedTR[0]]?.start_time;
    const te = timeline[debouncedTR[1]]?.end_time;
    fetchStats(ts != null && te != null ? { timeStart: ts, timeEnd: te } : {})
      .then(d => setStats(d.stats || {}))
      .catch(() => {});
  }, [loaded, debouncedTR, timeline]);

  // E6: recompute allProtocolKeysCountRef when stats/protocols change
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

  // E7: re-fetch graph when any filter changes (debounced)
  useEffect(() => {
    if (!loaded || !timeline.length) return;
    const ts = timeline[debouncedTR[0]]?.start_time;
    const te = timeline[debouncedTR[1]]?.end_time;
    const params = {};
    if (ts != null) params.timeStart = ts;
    if (te != null) params.timeEnd = te;
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
      const noneSelected = enabledP.size === 0 && allProtocolKeysCountRef.current > 0;
      setRawGraph(noneSelected ? { ...d, edges: [] } : d);
      if (!fullGraphRef.current) {
        fullGraphRef.current = { nodes: d.nodes || [], edges: d.edges || [] };
        fetchAlerts().then(al => setAlerts(al || { alerts: [], summary: {} })).catch(() => {});
      }
    }).catch(e => {
      if (e.name !== 'AbortError') console.error(e);
    });
    return () => ctrl.abort();
  }, [loaded, debouncedTR, enabledP, subnetG, debouncedSubnetPrefix, mergeByMac, includeIPv6, showHostnames, excludeBroadcasts, subnetExclusions, clusterAlgo, clusterResolution, timeline, protocols, setAlerts]);

  // E8: re-evaluate display filter when graph data changes
  useEffect(() => {
    if (!dfApplied) return;
    const result = applyDisplayFilter(dfApplied, graph.nodes || [], graph.edges || []);
    if (result?.error) { setDfError(result.error); setDfResult(null); }
    else { setDfResult(result); setDfError(null); }
  }, [graph, dfApplied]);

  // E9: client-side search
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

    const _SKIP_EDGE_KEYS = new Set([
      'id', 'source', 'target', 'protocol', 'type', 'synthetic',
      'total_bytes', 'packet_count', 'ports',
      'bytes_to_source', 'bytes_to_target', 'packets_to_source', 'packets_to_target',
    ]);
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
      for (const hint of _PROTO_HINTS) {
        if (hint.keyword.includes(q) && hint.keys.some(k => e[k]?.length)) return `has ${hint.keyword}`;
      }
      if (e.protocol_conflict && 'conflict'.includes(q)) return 'protocol conflict';
      return null;
    };

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

    if (sessions.length > 0) {
      for (const sess of sessions) {
        if (matchSession(sess)) {
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

  // E11: clear stale pathfind results when graph data changes
  useEffect(() => {
    if (rawGraph !== prevRawGraphRef.current) {
      prevRawGraphRef.current = rawGraph;
      selCallbacksRef.current.clearPathfindState?.();
    }
  }, [rawGraph]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Display filter handlers ──────────────────────────────────────

  function handleDfApply(expr) {
    if (!expr?.trim()) { setDfApplied(''); setDfResult(null); setDfError(null); return; }
    const result = applyDisplayFilter(expr, graph.nodes || [], graph.edges || []);
    if (result?.error) { setDfError(result.error); setDfResult(null); }
    else { setDfApplied(expr); setDfResult(result); setDfError(null); }
  }

  function handleDfClear() { setDfExpr(''); setDfApplied(''); setDfResult(null); setDfError(null); }

  // ── Slice URL ────────────────────────────────────────────────────

  function getSlicePcapUrl() {
    return slicePcapUrl({
      timeStart: timeline[filters.timeRange[0]]?.start_time,
      timeEnd:   timeline[filters.timeRange[1]]?.end_time,
      protocols: (enabledP.size < protocols.length && enabledP.size > 0) ? Array.from(enabledP).join(',') : undefined,
      search:    search || undefined,
      includeIPv6: includeIPv6 === false ? false : undefined,
    });
  }

  return {
    // Server data
    stats, timeline, rawGraph, sessions, fullSessions, sessionTotal,
    protocols, pColors, pluginResults, pluginSlots,
    // Derived
    graph, timeLabel, osGuesses, availableIps,
    // Search
    searchResult,
    // Display filter
    dfExpr, setDfExpr, dfApplied, dfError, dfResult,
    handleDfApply, handleDfClear,
    // Refs
    allProtocolKeysCountRef, fullGraphRef,
    // Graph setter
    setGraph,
    // Lifecycle
    initFromLoad, getSlicePcapUrl,
  };
}
