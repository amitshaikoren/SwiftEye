/**
 * useCapture — coordinator that wires the 5 domain slices and returns
 * the merged state object consumed by App.jsx.
 *
 * Decomposed in v0.25.0. See llm_docs/plans/active/usecapture-decomposition.md
 * for the full dependency map and wiring rationale.
 *
 * Slice creation order (dependency-driven):
 *   1. filters  — no deps on other slices (cross-refs populated later)
 *   2. annot    — needs setGraph via ref (set after data is created)
 *   3. data     — needs loaded, filters, setAlerts (from annot)
 *   4. sel      — needs search/setSearch (from filters), graph (from data)
 *   5. load     — needs onCaptureLoaded callback (fans out to all slices)
 *
 * Cross-slice callbacks use a shared ref (selCallbacksRef) that is updated
 * every render. This is safe because the callbacks are only invoked from
 * effects (which run post-render) or user-initiated handlers.
 */

import { useState, useRef, useMemo, useCallback } from 'react';
import { useAnimationMode } from './useAnimationMode';
import useEvents from './useEvents';
import { useCaptureFilters } from './useCaptureFilters';
import { useAnnotationsAndSynthetic } from './useAnnotationsAndSynthetic';
import { useCaptureData } from './useCaptureData';
import { useSelectionAndNavigation } from './useSelectionAndNavigation';
import { useCaptureLoad } from './useCaptureLoad';

export function useCapture() {

  // ── Independent sub-hooks (already decoupled) ────────────────────

  const anim = useAnimationMode();
  const evs = useEvents();

  // ── Lifted state (breaks circular deps between slices) ───────────

  const [loaded, setLoaded] = useState(false);

  // ── Cross-slice callback refs ────────────────────────────────────
  // Updated every render; read only from effects/handlers (post-render).

  const selCallbacksRef = useRef({});
  const setGraphRef = useRef(null);

  // ── Slice 1: Filters ─────────────────────────────────────────────

  const filters = useCaptureFilters({ selCallbacksRef });

  // ── Slice 2: Annotations & Synthetic ─────────────────────────────

  const annot = useAnnotationsAndSynthetic({ setGraphRef });

  // ── Slice 3: Data ────────────────────────────────────────────────

  const data = useCaptureData({
    loaded,
    filters,
    setAlerts: annot.setAlerts,
    selCallbacksRef,
  });

  // Wire setGraphRef now that data is created
  setGraphRef.current = data.setGraph;

  // ── Slice 4: Selection & Navigation ──────────────────────────────

  const sel = useSelectionAndNavigation({
    search: filters.search,
    setSearch: filters.setSearch,
    graph: data.graph,
  });

  // Update selCallbacksRef every render (sel is now created)
  selCallbacksRef.current = {
    clearSel: sel.clearSel,
    clearPathfindState: sel.clearPathfindState,
  };

  // ── Slice 5: Load ────────────────────────────────────────────────

  const onCaptureLoaded = useCallback((d) => {
    data.initFromLoad(d);
    annot.initFromLoad(d);
    filters.initFromLoad(d);
    setLoaded(true); // must be last — triggers refetch effects in data slice
  }, [data.initFromLoad, annot.initFromLoad, filters.initFromLoad]);

  const load = useCaptureLoad({
    loaded,
    setLoaded,
    onCaptureLoaded,
    setGraph: data.setGraph,
  });

  // ── Coordinator-level: handleCreateManualCluster ──────────────────
  // Crosses 3 slices (reads data.rawGraph, writes filters.manualClusters,
  // calls sel.clearSel), so it lives here.

  function handleCreateManualCluster(nodeIds) {
    if (!nodeIds || nodeIds.length < 2) return;
    const algoClusters = (filters.clusterAlgo && data.rawGraph.clusters) ? data.rawGraph.clusters : {};
    const allIds = [...Object.values(algoClusters), ...Object.values(filters.manualClusters)];
    const nextId = allIds.length > 0 ? Math.max(...allIds) + 1 : 0;
    filters.setManualClusters(prev => {
      const updated = { ...prev };
      for (const id of nodeIds) updated[id] = nextId;
      return updated;
    });
    sel.clearSel();
  }

  // ── Coordinator-level: visibleNodes/visibleEdges ──────────────────
  // Cross data.graph × sel.hiddenNodes — computed here.

  const visibleNodes = useMemo(
    () => (data.graph.nodes || []).filter(n => !sel.hiddenNodes.has(n.id)),
    [data.graph.nodes, sel.hiddenNodes]
  );
  const visibleEdges = useMemo(
    () => (data.graph.edges || []).filter(e => {
      const s = e.source?.id || e.source;
      const t = e.target?.id || e.target;
      return !sel.hiddenNodes.has(s) && !sel.hiddenNodes.has(t);
    }),
    [data.graph.edges, sel.hiddenNodes]
  );

  // ── Return the merged object (identical shape to pre-decomposition) ─

  return {
    // Lifecycle (load slice)
    loaded: load.loaded, loading: load.loading, loadMsg: load.loadMsg,
    error: load.error, fileName: load.fileName, sourceFiles: load.sourceFiles,
    handleUpload: load.handleUpload, handleDrop: load.handleDrop,
    handleFileInput: load.handleFileInput, handleMetadataInput: load.handleMetadataInput,
    schemaNegotiation: load.schemaNegotiation, schemaConfirming: load.schemaConfirming,
    handleSchemaConfirm: load.handleSchemaConfirm, handleSchemaCancel: load.handleSchemaCancel,
    typePicker: load.typePicker,
    handleTypePickerConfirm: load.handleTypePickerConfirm, handleTypePickerCancel: load.handleTypePickerCancel,

    // Data (data slice)
    stats: data.stats, timeline: data.timeline, graph: data.graph, rawGraph: data.rawGraph,
    sessions: data.sessions, sessionTotal: data.sessionTotal,
    protocols: data.protocols, pColors: data.pColors,
    pluginResults: data.pluginResults, pluginSlots: data.pluginSlots,

    // Derived (data slice + coordinator)
    visibleNodes, visibleEdges,
    timeLabel: data.timeLabel, osGuesses: data.osGuesses, availableIps: data.availableIps,

    // Filters (filters slice)
    timeRange: filters.timeRange, setTimeRange: filters.setTimeRange,
    enabledP: filters.enabledP, setEnabledP: filters.setEnabledP,
    search: filters.search, setSearch: filters.setSearch, searchResult: data.searchResult,
    collapseStatesRef: sel.collapseStatesRef,
    bucketSec: filters.bucketSec, setBucketSec: filters.setBucketSec,
    subnetG: filters.subnetG, setSubnetG: filters.setSubnetG, toggleSubnetG: filters.toggleSubnetG,
    labelThreshold: filters.labelThreshold, setLabelThreshold: filters.setLabelThreshold,
    graphWeightMode: filters.graphWeightMode, setGraphWeightMode: filters.setGraphWeightMode,
    edgeSizeMode: filters.edgeSizeMode, setEdgeSizeMode: filters.setEdgeSizeMode,
    nodeColorMode: filters.nodeColorMode, setNodeColorMode: filters.setNodeColorMode,
    edgeColorMode: filters.edgeColorMode, setEdgeColorMode: filters.setEdgeColorMode,
    nodeColorRules: filters.nodeColorRules, setNodeColorRules: filters.setNodeColorRules,
    edgeColorRules: filters.edgeColorRules, setEdgeColorRules: filters.setEdgeColorRules,
    showEdgeDirection: filters.showEdgeDirection, setShowEdgeDirection: filters.setShowEdgeDirection,
    subnetPrefix: filters.subnetPrefix, setSubnetPrefix: filters.setSubnetPrefix,
    mergeByMac: filters.mergeByMac, setMergeByMac: filters.setMergeByMac,
    includeIPv6: filters.includeIPv6, setIncludeIPv6: filters.setIncludeIPv6,
    showHostnames: filters.showHostnames, setShowHostnames: filters.setShowHostnames,
    excludeBroadcasts: filters.excludeBroadcasts, setExcludeBroadcasts: filters.setExcludeBroadcasts,
    clusterAlgo: filters.clusterAlgo, setClusterAlgo: filters.setClusterAlgo,
    clusterResolution: filters.clusterResolution, setClusterResolution: filters.setClusterResolution,
    clusterNames: filters.clusterNames, renameCluster: filters.renameCluster,
    clusterExclusions: filters.clusterExclusions,
    handleExpandCluster: filters.handleExpandCluster, handleCollapseCluster: filters.handleCollapseCluster,

    // Full-capture snapshots
    fullSessions: data.fullSessions, fullGraphRef: data.fullGraphRef,

    // Protocol key count ref
    allProtocolKeysCountRef: data.allProtocolKeysCountRef,

    // Display filter (data slice)
    dfExpr: data.dfExpr, setDfExpr: data.setDfExpr,
    dfApplied: data.dfApplied, dfError: data.dfError, dfResult: data.dfResult,
    handleDfApply: data.handleDfApply, handleDfClear: data.handleDfClear,

    // Annotations (annot slice)
    annotations: annot.annotations,
    handleAddAnnotation: annot.handleAddAnnotation,
    handleUpdateAnnotation: annot.handleUpdateAnnotation,
    handleDeleteAnnotation: annot.handleDeleteAnnotation,
    handleAddNodeAnnotation: annot.handleAddNodeAnnotation,
    handleAddEdgeAnnotation: annot.handleAddEdgeAnnotation,

    // Alerts (annot slice)
    alerts: annot.alerts, setAlerts: annot.setAlerts,

    // Synthetic (annot slice + coordinator)
    handleAddSyntheticNode: annot.handleAddSyntheticNode,
    handleAddSyntheticEdge: annot.handleAddSyntheticEdge,
    handleDeleteSynthetic: annot.handleDeleteSynthetic,
    handleUpdateSyntheticNode: annot.handleUpdateSyntheticNode,
    handleSaveNote: annot.handleSaveNote,
    handleCreateManualCluster,
    handleUnclusterSubnet: filters.handleUnclusterSubnet,

    // Selection (sel slice)
    selNodes: sel.selNodes, selEdge: sel.selEdge,
    selSession: sel.selSession, selSessionSiblings: sel.selSessionSiblings, rPanel: sel.rPanel,
    handleGSel: sel.handleGSel, selectSession: sel.selectSession,
    selectSessionWithContext: sel.selectSessionWithContext,
    selectNodePanel: sel.selectNodePanel, switchPanel: sel.switchPanel,
    clearSel: sel.clearSel, clearAll: sel.clearAll,
    navBack: sel.navBack, navForward: sel.navForward,
    canGoBack: sel.canGoBack, canGoForward: sel.canGoForward,
    handleInvestigate: sel.handleInvestigate,
    handleInvestigateNeighbours: sel.handleInvestigateNeighbours,
    exitInvestigation: sel.exitInvestigation,

    // Investigation & hidden (sel slice)
    investigatedIp: sel.investigatedIp, investigationNodes: sel.investigationNodes,
    hiddenNodes: sel.hiddenNodes, handleHideNode: sel.handleHideNode, handleUnhideAll: sel.handleUnhideAll,

    // Pathfinding (sel slice)
    pathfindSource: sel.pathfindSource, startPathfind: sel.startPathfind,
    cancelPathfind: sel.cancelPathfind, executePathfind: sel.executePathfind,
    pathfindResult: sel.pathfindResult, pathfindLoading: sel.pathfindLoading,
    runPathfindFromPanel: sel.runPathfindFromPanel,
    seqAckSessionId: sel.seqAckSessionId, setSeqAckSessionId: sel.setSeqAckSessionId,

    // Panel (sel slice)
    panelWidth: sel.panelWidth, setPanelWidth: sel.setPanelWidth,
    handlePanelDragStart: sel.handlePanelDragStart,
    getSlicePcapUrl: data.getSlicePcapUrl,

    // Graph setter (data slice)
    setGraph: data.setGraph,

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
    rejectSuggestion: evs.rejectSuggestion,
    rulerOn: evs.rulerOn,
    setRulerOn: evs.setRulerOn,
    nodeEventSeverity: evs.nodeEventSeverity,
    edgeEventSeverity: evs.edgeEventSeverity,
    getEventsForEntity: evs.getEventsForEntity,
    flaggingTarget: load.flaggingTarget,
    openFlagModal: load.openFlagModal,
    closeFlagModal: load.closeFlagModal,
  };
}
