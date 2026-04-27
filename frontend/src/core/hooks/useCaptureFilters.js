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
import { useWorkspace } from '@/WorkspaceProvider';

const TIME_RANGE_DEBOUNCE_MS = 300;

// Network-shape fallback if a workspace omits graphDisplay entirely. Keeps
// pre-Phase-5.7 behaviour for any descriptor that hasn't migrated yet.
const _DEFAULT_GRAPH_DISPLAY_DEFAULTS = {
  nodeWeight: 'bytes',
  edgeWeight: 'bytes',
  nodeColor:  'address',
  edgeColor:  'protocol',
};

export function useCaptureFilters({ selCallbacksRef }) {
  const workspace = useWorkspace();
  const gdDefaults = workspace.graphDisplay?.defaults || _DEFAULT_GRAPH_DISPLAY_DEFAULTS;

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

  // ── Edge-type visibility (used by forensic artifact browser) ─────
  // Set of edge `type` values that are currently hidden.
  // Empty = all visible. Network workspace never populates this.

  const [hiddenEdgeTypes, setHiddenEdgeTypes] = useState(new Set());

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

  // ── Graph display options (view-only, no effects) ────────────────
  //
  // Defaults come from the active workspace's `graphDisplay.defaults`
  // (Phase 5.7). Switching workspaces is a full app reload today, so
  // initial state is sufficient — no reset effect needed.

  const [labelThreshold, setLabelThreshold]   = useState(0);
  const [graphWeightMode, setGraphWeightMode] = useState(gdDefaults.nodeWeight);
  const [edgeSizeMode, setEdgeSizeMode]       = useState(gdDefaults.edgeWeight);
  const [nodeColorMode, setNodeColorMode]     = useState(gdDefaults.nodeColor);
  const [edgeColorMode, setEdgeColorMode]     = useState(gdDefaults.edgeColor);
  const [nodeColorRules, setNodeColorRules]   = useState([]);
  const [edgeColorRules, setEdgeColorRules]   = useState([]);

  // Resolved mode → field+scale for the renderer. Computed here so consumers
  // (App.jsx → GraphCanvas → useGraphSim) don't need workspace-context access.
  // If a mode id falls out of sync with the catalog (workspace switch race or
  // a deleted mode), we fall back to the catalog's first entry.
  const _nwModes = workspace.graphDisplay?.nodeWeightModes || [];
  const _ewModes = workspace.graphDisplay?.edgeWeightModes || [];
  const _nwMode = _nwModes.find(m => m.id === graphWeightMode) || _nwModes[0] || null;
  const _ewMode = _ewModes.find(m => m.id === edgeSizeMode)    || _ewModes[0] || null;
  const nodeWeightField = _nwMode?.field || 'total_bytes';
  const nodeWeightScale = _nwMode?.scale || 'log';
  const edgeWeightField = _ewMode?.field || 'total_bytes';
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
    setEnabledP(new Set(enabledProtocolKeys || []));
    setHiddenEdgeTypes(new Set());
    const len = timelineLength || 0;
    const fullRange = len > 0 ? [0, len - 1] : [0, 0];
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
    // Edge-type visibility
    hiddenEdgeTypes, setHiddenEdgeTypes,
    // Search
    search, setSearch,
    // Bucket
    bucketSec, setBucketSec,
    // Subnet
    subnetG, setSubnetG, toggleSubnetG,
    subnetPrefix, setSubnetPrefix: setSubnetPrefixOuter, debouncedSubnetPrefix,
    subnetExclusions, handleUnclusterSubnet,
    // Display options
    labelThreshold, setLabelThreshold,
    graphWeightMode, setGraphWeightMode,
    edgeSizeMode, setEdgeSizeMode,
    nodeColorMode, setNodeColorMode,
    edgeColorMode, setEdgeColorMode,
    nodeColorRules, setNodeColorRules,
    edgeColorRules, setEdgeColorRules,
    showEdgeDirection, setShowEdgeDirection,
    // Resolved (mode-id → field+scale) — consumed by GraphCanvas/useGraphSim.
    nodeWeightField, nodeWeightScale, edgeWeightField,
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
