/**
 * useCaptureFilters — all filter UI state, debounced setters, cluster/subnet
 * state, view-only display options.
 *
 * Extracted from useCapture as part of the decomposition (v0.25.0).
 *
 * Cross-slice params (via refs, populated by coordinator after all slices init):
 *   - selCallbacksRef.current.clearSel — for E12 (search change clears selection)
 */

import { useState, useRef, useEffect, useCallback } from 'react';

const TIME_RANGE_DEBOUNCE_MS = 300;

export function useCaptureFilters({ selCallbacksRef }) {

  // ── Time range ───────────────────────────────────────────────────

  const [timeRange, setTimeRange]     = useState([0, 0]);
  const [debouncedTR, setDebouncedTR] = useState([0, 0]);
  const trTimerRef = useRef(null);
  const setTimeRangeOuter = useCallback((v) => {
    setTimeRange(v);
    clearTimeout(trTimerRef.current);
    trTimerRef.current = setTimeout(() => setDebouncedTR(v), TIME_RANGE_DEBOUNCE_MS);
  }, []);

  // ── Protocol filter ──────────────────────────────────────────────

  const [enabledP, setEnabledP] = useState(new Set());

  // ── Search ───────────────────────────────────────────────────────

  const [search, setSearch] = useState('');

  // E12: clear selection when search text changes
  const prevSearchRef = useRef('');
  useEffect(() => {
    if (prevSearchRef.current && prevSearchRef.current !== search) {
      selCallbacksRef.current.clearSel?.();
    }
    prevSearchRef.current = search;
  }, [search]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Bucket size ──────────────────────────────────────────────────

  const [bucketSec, setBucketSec] = useState(15);

  // ── Subnet grouping ──────────────────────────────────────────────

  const [subnetG, setSubnetG] = useState(false);
  const [subnetPrefix, setSubnetPrefix] = useState(24);
  const [debouncedSubnetPrefix, setDebouncedSubnetPrefix] = useState(24);
  const spTimerRef = useRef(null);
  const setSubnetPrefixOuter = useCallback((v) => {
    setSubnetPrefix(v);
    clearTimeout(spTimerRef.current);
    spTimerRef.current = setTimeout(() => setDebouncedSubnetPrefix(v), 400);
  }, []);
  const [subnetExclusions, setSubnetExclusions] = useState(new Set());

  function toggleSubnetG() {
    setSubnetG(prev => {
      if (prev) setSubnetExclusions(p => p.size === 0 ? p : new Set());
      return !prev;
    });
  }

  function handleUnclusterSubnet(subnetId) {
    setSubnetExclusions(prev => {
      if (prev.has(subnetId)) return prev;
      return new Set([...prev, subnetId]);
    });
  }

  // ── Graph layout ─────────────────────────────────────────────────

  const [layoutMode, setLayoutMode] = useState('force');
  const [layoutFocusNodeId, setLayoutFocusNodeId] = useState(null);

  // ── Graph display options (view-only, no effects) ────────────────

  const [labelThreshold, setLabelThreshold]   = useState(0);
  const [graphWeightMode, setGraphWeightMode] = useState('bytes');
  const [edgeSizeMode, setEdgeSizeMode]       = useState('bytes');
  const [nodeColorMode, setNodeColorMode]     = useState('address');
  const [edgeColorMode, setEdgeColorMode]     = useState('protocol');
  const [nodeColorRules, setNodeColorRules]   = useState([]);
  const [edgeColorRules, setEdgeColorRules]   = useState([]);
  const [showEdgeDirection, setShowEdgeDirection] = useState(false);

  // ── Merge / IPv6 / hostname / broadcast toggles ──────────────────

  const [mergeByMac, setMergeByMac]               = useState(false);
  const [includeIPv6, setIncludeIPv6]             = useState(true);
  const [showHostnames, setShowHostnames]         = useState(true);
  const [excludeBroadcasts, setExcludeBroadcasts] = useState(false);

  // ── Cluster state ────────────────────────────────────────────────

  const [clusterAlgo, setClusterAlgo]             = useState('');
  const [clusterResolution, setClusterResolution] = useState(1.0);
  const [clusterNames, setClusterNames]           = useState({});
  const [clusterExclusions, setClusterExclusions] = useState(new Set());
  const [manualClusters, setManualClusters]       = useState({});

  // E10: reset cluster state when algorithm changes
  const prevAlgoRef = useRef(clusterAlgo);
  useEffect(() => {
    if (clusterAlgo !== prevAlgoRef.current) {
      setClusterNames({});
      setClusterExclusions(new Set());
      setManualClusters({});
      prevAlgoRef.current = clusterAlgo;
    }
  }, [clusterAlgo]);

  function handleExpandCluster(clusterId) {
    setClusterExclusions(prev => {
      if (prev.has(clusterId)) return prev;
      return new Set([...prev, clusterId]);
    });
  }

  function handleCollapseCluster(clusterId) {
    setClusterExclusions(prev => {
      if (!prev.has(clusterId)) return prev;
      const s = new Set(prev); s.delete(clusterId); return s;
    });
  }

  // ── Init from full-capture load ──────────────────────────────────

  const initFromLoad = useCallback(({ enabledProtocolKeys, timelineLength }) => {
    setEnabledP(new Set(enabledProtocolKeys));
    const fullRange = [0, timelineLength - 1];
    setTimeRange(fullRange);
    setDebouncedTR(fullRange);
  }, []);

  // ── Reset time range (called by data slice on bucket refetch) ────

  const resetTimeRange = useCallback((timelineLength) => {
    const full = [0, timelineLength - 1];
    setTimeRange(full);
    setDebouncedTR(full);
  }, []);

  return {
    // Time range
    timeRange, setTimeRange: setTimeRangeOuter, debouncedTR,
    // Protocol
    enabledP, setEnabledP,
    // Search
    search, setSearch,
    // Bucket
    bucketSec, setBucketSec,
    // Subnet
    subnetG, setSubnetG, toggleSubnetG,
    subnetPrefix, setSubnetPrefix: setSubnetPrefixOuter, debouncedSubnetPrefix,
    subnetExclusions, handleUnclusterSubnet,
    // Layout
    layoutMode, setLayoutMode,
    layoutFocusNodeId, setLayoutFocusNodeId,
    // Display options
    labelThreshold, setLabelThreshold,
    graphWeightMode, setGraphWeightMode,
    edgeSizeMode, setEdgeSizeMode,
    nodeColorMode, setNodeColorMode,
    edgeColorMode, setEdgeColorMode,
    nodeColorRules, setNodeColorRules,
    edgeColorRules, setEdgeColorRules,
    showEdgeDirection, setShowEdgeDirection,
    // Merge/IPv6/hostname/broadcast
    mergeByMac, setMergeByMac,
    includeIPv6, setIncludeIPv6,
    showHostnames, setShowHostnames,
    excludeBroadcasts, setExcludeBroadcasts,
    // Cluster
    clusterAlgo, setClusterAlgo,
    clusterResolution, setClusterResolution,
    clusterNames, renameCluster: (id, name) => setClusterNames(prev => ({ ...prev, [id]: name })),
    clusterExclusions, handleExpandCluster, handleCollapseCluster,
    manualClusters, setManualClusters,
    // Lifecycle
    initFromLoad, resetTimeRange,
  };
}
