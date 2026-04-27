/**
 * App.jsx — pure layout and routing.
 * All state/logic lives in useCapture(). This file only renders.
 */

import React, { useState, useEffect, useRef, useMemo, lazy, Suspense } from 'react';
import { useCapture } from './core/hooks/useCapture';
import { fetchSessionDetail } from './core/api';
import { useSettings } from './core/hooks/useSettings';
import { FilterContext, toProtocolNames } from './core/FilterContext';
import { useWorkspace } from './WorkspaceProvider';
import TopBar from './core/components/TopBar';
import LeftPanel from './core/components/LeftPanel';
import GraphCanvas from './core/components/GraphCanvas';
import TimelineStrip from './core/components/TimelineStrip';
import AlertsPanel from './core/components/AlertsPanel';
import InvestigationPage from './core/components/InvestigationPage';
import VisualizePage from './core/components/VisualizePage';
import ClusterLegend from './workspaces/network/ClusterLegend';
import SchemaDialog from './core/components/SchemaDialog';
import TypePickerDialog from './core/components/TypePickerDialog';
import SettingsPanel from './core/components/SettingsPanel';
import EventFlagModal from './core/components/EventFlagModal';
import AppRightPanel from './core/components/AppRightPanel';

// Heavy panels: loaded on first activation only (code-split to reduce initial bundle)
const ResearchPage  = lazy(() => import('./core/components/ResearchPage'));
const AnalysisPage  = lazy(() => import('./core/components/AnalysisPage'));
const AnimationPane = lazy(() => import('./core/components/AnimationPane'));

export default function App() {
  const c = useCapture();
  const workspace = useWorkspace();
  const FilterBar = workspace.FilterBar;
  const UploadScreen = workspace.UploadScreen;
  const LeftPanelTop = workspace.LeftPanelTop;

  // Workspace-specific top bar stats (null = use default packet count)
  const topBarStats = workspace.getTopBarStats
    ? workspace.getTopBarStats(c.stats, c.visibleNodes.length)
    : null;

  // Pre-instantiate the workspace left-panel top section with the props it needs
  const leftPanelTop = LeftPanelTop ? (
    <LeftPanelTop
      graph={c.graph}
      hiddenEdgeTypes={c.hiddenEdgeTypes}
      setHiddenEdgeTypes={c.setHiddenEdgeTypes}
      schema={workspace.schema}
    />
  ) : null;
  const { settings, setSetting } = useSettings();
  const [showSettings, setShowSettings] = useState(false);
  const [queryHighlight, setQueryHighlight] = useState(null);  // { nodes: Set, edges: Set }
  // InvestigationPage tab state lifted here so the back-to-timeline breadcrumb
  // can restore whichever tab the user was on when they hit "View in graph".
  const [investigationTab, setInvestigationTab] = useState('documentation');
  // When the user hits "View in graph" from inside InvestigationPage, we
  // remember which tab they came from so the floating breadcrumb on the main
  // graph view can offer a one-click return. null = breadcrumb hidden.
  const [returnToInvestigationTab, setReturnToInvestigationTab] = useState(null);
  // Once the user is back on the investigation panel (whether via the
  // breadcrumb or by clicking the left-nav button manually), the breadcrumb
  // has nothing to point at — clear it so it doesn't reappear next time they
  // visit the main graph view.
  useEffect(() => {
    if (c.rPanel === 'investigation' && returnToInvestigationTab !== null) {
      setReturnToInvestigationTab(null);
    }
  }, [c.rPanel, returnToInvestigationTab]);

  // ── Subgraph-scoped stats (when investigation is active) ─────────
  const subgraphInfo = useMemo(() => {
    if (!c.investigationNodes || !c.graph?.edges) return null;
    const inv = c.investigationNodes;
    const edges = c.graph.edges.filter(e => {
      const sId = typeof e.source === 'object' ? e.source.id : e.source;
      const tId = typeof e.target === 'object' ? e.target.id : e.target;
      return inv.has(sId) && inv.has(tId);
    });
    const bytes = edges.reduce((s, e) => s + (e.total_bytes || 0), 0);
    const packets = edges.reduce((s, e) => s + (e.packet_count || 0), 0);
    return { nodes: inv.size, connections: edges.length, bytes, packets };
  }, [c.investigationNodes, c.graph]);

  // ── Centralized filter context value ────────────────────────────
  const filterValue = useMemo(() => ({
    timeRange: c.timeRange,
    enabledP: c.enabledP,
    search: c.search,
    includeIPv6: c.includeIPv6,
    protocolList: c.protocols,
    allProtocolKeysCount: c.allProtocolKeysCountRef.current,
  }), [c.timeRange, c.enabledP, c.search, c.includeIPv6, c.protocols]);
  // Note: allProtocolKeysCount is from a ref — updated by a separate effect in useCapture.
  // It's stable once the capture is loaded so it doesn't need to be a dep here.

  // ── Animation node positions — persists across panel switches ──────
  // AnimationPane is unmounted when switching to full-width panels (Research,
  // Timeline, etc.). Keeping positions here means dragged positions survive
  // those navigation detours.
  const animSavedPositionsRef = useRef({});

  // ── Graph container size (for Sparkline width) ───────────────────
  const graphContainerRef = useRef(null);
  const [gSize, setGS] = useState({ width: 800, height: 600 });
  useEffect(() => {
    const el = graphContainerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(es => {
      for (const e of es) setGS({ width: e.contentRect.width, height: e.contentRect.height });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // ── Upload / loading screen ──────────────────────────────────────
  // Unloaded-state UI is workspace-owned. Network provides a pcap/Zeek
  // drop-zone; forensic provides a "skeleton — not yet available" stub.
  // A workspace that omits UploadScreen gets a minimal fallback.
  if (!c.loaded) {
    if (UploadScreen) {
      return (
        <UploadScreen
          visualize={c.rPanel === 'visualize'}
          loading={c.loading}
          loadMsg={c.loadMsg}
          handleDrop={c.handleDrop}
          handleFileInput={c.handleFileInput}
          error={c.error}
          switchPanel={c.switchPanel}
          schemaNegotiation={c.schemaNegotiation}
          handleSchemaConfirm={c.handleSchemaConfirm}
          handleSchemaCancel={c.handleSchemaCancel}
          schemaConfirming={c.schemaConfirming}
          typePicker={c.typePicker}
          handleTypePickerConfirm={c.handleTypePickerConfirm}
          handleTypePickerCancel={c.handleTypePickerCancel}
        />
      );
    }
    return (
      <div style={{ width: '100%', height: '100vh', background: 'var(--bg)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        color: 'var(--txD)', fontFamily: 'var(--fn)', fontSize: 13 }}>
        No ingestion configured for workspace: {workspace.label || workspace.name}
      </div>
    );
  }

  // ── Main layout ──────────────────────────────────────────────────
  return (
    <FilterContext.Provider value={filterValue}>
    <div style={{ height: '100vh', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <TopBar
        fileName={c.fileName}
        sourceFiles={c.sourceFiles}
        stats={c.stats}
        search={c.search} setSearch={c.setSearch}
        searchResult={c.searchResult}
        onSelectNode={id => c.handleGSel('node', id, false)}
        onSelectEdge={e => c.handleGSel('edge', e, false)}
        onNewFile={() => document.getElementById('pcap-re').click()}
        onMetadataFile={() => document.getElementById('meta-up').click()}
        onSettings={() => setShowSettings(true)}
        onLogoClick={() => { c.switchPanel('stats'); c.setSearch(''); if (c.animActive) c.stopAnimation(); }}
        workspaceName={workspace.name}
        availableWorkspaces={workspace.available}
        topBarStats={topBarStats}
      />
      {FilterBar && (
        <FilterBar
          value={c.dfExpr}
          onChange={c.setDfExpr}
          onApply={c.handleDfApply}
          onClear={c.handleDfClear}
          matchCount={c.dfResult?.matchCount ?? null}
          error={c.dfError}
          isActive={!!c.dfApplied && !c.dfError}
          osGuesses={c.osGuesses}
          activeOsFilter={c.dfApplied.startsWith('os ') ? c.dfApplied : ''}
        />
      )}

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {/* LEFT PANEL — always visible */}
        <LeftPanel
          protocols={c.protocols} pColors={c.pColors}
          enabledP={c.enabledP} setEnabledP={c.setEnabledP}
          graph={c.graph} stats={c.stats}
          rPanel={c.rPanel} switchPanel={c.switchPanel}
          sessionTotal={c.sessionTotal} sessionFiltered={c.sessions.length} activeSearch={c.search}
          selNodes={c.selNodes} clearSel={c.clearSel}
          selEdge={c.selEdge} selSession={c.selSession}
          onApplyDisplayFilter={expr => { c.setDfExpr(expr); c.handleDfApply(expr); }}
          activeOsFilter={c.dfApplied.startsWith('os ') ? c.dfApplied : ''}
          osGuesses={c.osGuesses}
          queryActive={!!queryHighlight}
          alertSummary={c.alerts.summary}
          leftPanelTop={leftPanelTop}
          supportedTabs={workspace.supportedTabs ?? null}
        />

        {c.rPanel === 'research' ? (
          /* RESEARCH PAGE — full width, replaces graph + right panel */
          <Suspense fallback={<div style={{ padding: 24, color: 'var(--txD)', fontSize: 12 }}>Loading…</div>}>
            <ResearchPage
              investigatedIp={c.investigatedIp}
              seqAckSessionId={c.seqAckSessionId}
              searchIp={/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(c.search.trim()) ? c.search.trim() : ''}
              availableIps={c.availableIps}
              timeline={c.timeline}
              timeRange={c.timeRange} setTimeRange={c.setTimeRange}
              bucketSec={c.bucketSec} setBucketSec={c.setBucketSec}
            />
          </Suspense>
        ) : c.rPanel === 'analysis' ? (
          /* ANALYSIS PAGE — full width, replaces graph + right panel */
          <Suspense fallback={<div style={{ padding: 24, color: 'var(--txD)', fontSize: 12 }}>Loading…</div>}>
            <AnalysisPage
              nodes={c.visibleNodes}
              edges={c.visibleEdges}
              sessions={c.sessions}
              pColors={c.pColors}
              onSelectNode={c.selectNodePanel}
              filters={{
                timeStart:      c.timeRange?.[0] ?? null,
                timeEnd:        c.timeRange?.[1] ?? null,
                protocols:      c.enabledP ? Array.from(c.enabledP) : null,
                search:         c.search || '',
                includeIPv6:    c.includeIPv6 !== false,
                subnetGrouping: c.subnetGrouping || false,
                subnetPrefix:   c.subnetPrefix   || 24,
                mergeByMac:     c.mergeByMac     || false,
              }}
              selection={{
                nodeIds:   c.selNodes ? Array.from(c.selNodes) : [],
                edgeId:    c.selEdge    || null,
                sessionId: c.selSession?.id || null,
                alertId:   null,
              }}
            />
          </Suspense>
        ) : c.rPanel === 'alerts' ? (
          /* ALERTS PAGE — full width, security pattern findings */
          <AlertsPanel
            alerts={c.alerts.alerts}
            summary={c.alerts.summary}
            onShowInGraph={(alert) => {
              const nodes = new Set(alert.node_ids || []);
              const edges = new Set(alert.edge_ids || []);
              if (nodes.size || edges.size) {
                setQueryHighlight({ nodes, edges });
              }
              c.switchPanel('stats');
            }}
          />
        ) : c.rPanel === 'investigation' ? (
          /* INVESTIGATION PAGE — markdown notebook + Timeline Graph (v0.21.0) */
          <InvestigationPage
            events={c.events}
            timelineEdges={c.timelineEdges}
            suggestedEdges={c.suggestedEdges}
            addTimelineEdge={c.addTimelineEdge}
            removeTimelineEdge={c.removeTimelineEdge}
            acceptSuggestion={c.acceptSuggestion}
            rejectSuggestion={c.rejectSuggestion}
            rulerOn={c.rulerOn}
            setRulerOn={c.setRulerOn}
            placeEvent={c.placeEvent}
            unplaceEvent={c.unplaceEvent}
            removeEvent={c.removeEvent}
            updateEvent={c.updateEvent}
            tab={investigationTab}
            setTab={setInvestigationTab}
            onSelectEntity={(entity_type, entity_id) => {
              if (!entity_type || !entity_id) return;
              // Remember which tab the user was on so the floating breadcrumb
              // on the main graph view can offer a one-click return.
              setReturnToInvestigationTab(investigationTab);
              // Switch to the main graph view FIRST. switchPanel calls
              // clearSel() internally, so any selection or highlight we set
              // afterwards survives the React 18 setState batching (last write
              // wins per state slot in the same event handler).
              c.switchPanel('stats');
              if (entity_type === 'node') {
                const node = c.graph?.nodes?.find(n => n.id === entity_id);
                if (node) c.handleGSel('node', node, false);
                // Pulse-highlight the node in the main GraphCanvas so the
                // user can see WHERE the entity lives after switching tabs.
                setQueryHighlight({ nodes: new Set([entity_id]), edges: new Set() });
              } else if (entity_type === 'edge') {
                const edge = c.graph?.edges?.find(e => e.id === entity_id);
                if (edge) c.handleGSel('edge', edge, false);
                // Edge IDs are already in the canonical "u|v" form GraphCanvas expects.
                // Also light up both endpoint nodes for context.
                const endpoints = new Set();
                if (edge?.source) endpoints.add(typeof edge.source === 'object' ? edge.source.id : edge.source);
                if (edge?.target) endpoints.add(typeof edge.target === 'object' ? edge.target.id : edge.target);
                setQueryHighlight({ nodes: endpoints, edges: new Set([entity_id]) });
              } else if (entity_type === 'session') {
                fetchSessionDetail(entity_id, 0).then(d => {
                  if (d.session) {
                    c.selectSession(d.session);
                    // Resolve session src_ip / dst_ip to node IDs (which may
                    // be a CIDR for subnetted nodes), so the highlight ring
                    // lights up the right hosts on the canvas.
                    const findNodeId = (ip) => {
                      if (!ip) return null;
                      const direct = c.graph?.nodes?.find(n => n.id === ip);
                      if (direct) return direct.id;
                      const byIps = c.graph?.nodes?.find(n => n.ips?.includes(ip));
                      return byIps?.id || null;
                    };
                    const nodes = new Set();
                    const sId = findNodeId(d.session.src_ip);
                    const tId = findNodeId(d.session.dst_ip);
                    if (sId) nodes.add(sId);
                    if (tId) nodes.add(tId);
                    const edges = new Set();
                    if (sId && tId) {
                      // Edge IDs are the canonical "u|v" form (sorted) — try both.
                      edges.add(`${sId}|${tId}`);
                      edges.add(`${tId}|${sId}`);
                    }
                    if (nodes.size) setQueryHighlight({ nodes, edges });
                  }
                }).catch(() => {});
              }
            }}
          />
        ) : c.rPanel === 'visualize' ? (
          /* VISUALIZE PAGE — full width, custom data graph */
          <VisualizePage />
        ) : (
          <>
            {/* CENTER — graph + timeline strip */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
              {/* Graph area */}
              <div ref={graphContainerRef} style={{ flex: 1, position: 'relative', overflow: 'hidden', background: 'var(--bg)' }}>

                {/* Back-to-investigation breadcrumb (after "View in graph" from InvestigationPage) */}
                {!c.animActive && returnToInvestigationTab && (
                  <div style={{
                    position: 'absolute', top: 8, left: 8, zIndex: 12,
                    display: 'flex', alignItems: 'center', gap: 6,
                    background: 'rgba(88,166,255,.12)', border: '1px solid rgba(88,166,255,.35)',
                    borderRadius: 6, padding: '4px 8px 4px 10px',
                    boxShadow: '0 2px 6px rgba(0,0,0,.35)',
                    fontFamily: 'var(--fn)',
                  }}>
                    <button
                      onClick={() => {
                        const dest = returnToInvestigationTab;
                        setInvestigationTab(dest);
                        setReturnToInvestigationTab(null);
                        c.switchPanel('investigation');
                      }}
                      style={{
                        background: 'none', border: 'none', color: '#58a6ff',
                        fontSize: 11, fontFamily: 'var(--fn)', cursor: 'pointer',
                        padding: 0, display: 'flex', alignItems: 'center', gap: 4,
                      }}>
                      <span style={{ fontSize: 13, lineHeight: 1 }}>←</span>
                      Back to {returnToInvestigationTab === 'timeline' ? 'Timeline Graph' : 'Documentation'}
                    </button>
                    <button
                      onClick={() => setReturnToInvestigationTab(null)}
                      title="Dismiss"
                      style={{
                        background: 'none', border: 'none', color: '#8b949e',
                        fontSize: 12, lineHeight: 1, cursor: 'pointer',
                        padding: '0 2px', marginLeft: 2,
                      }}>×</button>
                  </div>
                )}

                {/* Hidden nodes badge (hidden in animation mode) */}
                {!c.animActive && c.hiddenNodes.size > 0 && (
                  <div style={{
                    position: 'absolute', top: c.investigatedIp ? 38 : 8, right: 8, zIndex: 10,
                    display: 'flex', alignItems: 'center', gap: 6,
                    background: 'rgba(248,81,73,.12)', border: '1px solid rgba(248,81,73,.3)',
                    borderRadius: 6, padding: '4px 10px', fontSize: 10,
                  }}>
                    <span style={{ color: '#f85149' }}>{c.hiddenNodes.size} node{c.hiddenNodes.size > 1 ? 's' : ''} hidden</span>
                    <button className="btn" onClick={c.handleUnhideAll}
                      style={{ fontSize: 9, padding: '1px 6px', borderColor: 'rgba(248,81,73,.4)', color: '#f85149' }}>Unhide all</button>
                  </div>
                )}

                {/* Pathfind pick-target banner (hidden in animation mode) */}
                {!c.animActive && c.pathfindSource && (
                  <div style={{
                    position: 'absolute', top: 0, left: 0, right: 0, zIndex: 11,
                    background: 'rgba(227,179,65,.12)', borderBottom: '1px solid rgba(227,179,65,.3)',
                    padding: '5px 12px', display: 'flex', alignItems: 'center', gap: 8,
                  }}>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#e3b341" strokeWidth="2">
                      <circle cx="5" cy="19" r="3"/><circle cx="19" cy="5" r="3"/>
                      <path d="M5 16V9a4 4 0 014-4h6"/><polyline points="15 1 19 5 15 9"/>
                    </svg>
                    <span style={{ fontSize: 11, color: '#e3b341', fontFamily: 'var(--fn)' }}>
                      Find paths from <strong>{c.pathfindSource}</strong> — click a target node
                    </span>
                    <button onClick={c.cancelPathfind} style={{
                      marginLeft: 'auto', fontSize: 10, color: '#8b949e',
                      background: 'none', border: '1px solid #30363d', borderRadius: 4,
                      padding: '2px 8px', cursor: 'pointer', fontFamily: 'var(--fn)',
                    }}>Cancel</button>
                  </div>
                )}

                {/* Investigation banner (hidden in animation mode) */}
                {!c.animActive && c.investigatedIp && (
                  <div style={{
                    position: 'absolute', top: 0, left: 0, right: 0, zIndex: 10,
                    background: 'rgba(88,166,255,.12)', borderBottom: '1px solid rgba(88,166,255,.3)',
                    padding: '5px 12px', display: 'flex', alignItems: 'center', gap: 8,
                  }}>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" strokeWidth="2">
                      <circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
                    </svg>
                    <span style={{ fontSize: 11, color: '#58a6ff', fontFamily: 'var(--fn)' }}>
                      {c.pathfindResult ? 'Paths' : 'Investigating'}: <strong>{c.investigatedIp}</strong>
                      {c.pathfindResult ? (
                        <span style={{ color: '#484f58', fontWeight: 400 }}> — {c.pathfindResult.path_count} path(s) found, {c.investigationNodes?.size || 0} nodes</span>
                      ) : c.investigationNodes ? (
                        <span style={{ color: '#484f58', fontWeight: 400 }}> — {c.investigationNodes.size} nodes in component</span>
                      ) : null}
                    </span>
                    <button onClick={c.exitInvestigation} style={{
                      marginLeft: 'auto', fontSize: 10, color: '#8b949e',
                      background: 'none', border: '1px solid #30363d', borderRadius: 4,
                      padding: '2px 8px', cursor: 'pointer', fontFamily: 'var(--fn)',
                    }}>Exit</button>
                  </div>
                )}

                {c.animActive ? (
                  <Suspense fallback={<div style={{ padding: 24, color: 'var(--txD)', fontSize: 12 }}>Loading…</div>}>
                    <AnimationPane
                      animNodes={c.animNodes}
                      animEvents={c.animEvents}
                      animNodeMeta={c.animNodeMeta}
                      animFrame={c.animFrame}
                      animPlaying={c.animPlaying}
                      animSpeed={c.animSpeed}
                      animOpts={c.animOpts}
                      frameState={c.frameState}
                      currentEvent={c.currentEvent}
                      animTimeRange={c.animTimeRange}
                      totalFrames={c.totalFrames}
                      isIsolated={c.isIsolated}
                      togglePlay={c.togglePlay}
                      goToFrame={c.goToFrame}
                      stepForward={c.stepForward}
                      stepBackward={c.stepBackward}
                      goToStart={c.goToStart}
                      goToEnd={c.goToEnd}
                      setAnimSpeed={c.setAnimSpeed}
                      setAnimOpts={c.setAnimOpts}
                      setIsIsolated={c.setIsIsolated}
                      stopAnimation={c.stopAnimation}
                      mainNodes={c.graph?.nodes || []}
                      pColors={c.pColors}
                      savedPositionsRef={animSavedPositionsRef}
                      onSelectNode={id => id ? c.handleGSel('node', id, false) : c.clearSel()}
                      onSelectSession={sid => {
                        const sess = c.sessions.find(s => s.id === sid);
                        if (sess) { c.selectSession(sess); return; }
                        // Session not in local list (capped at 1000) — fetch from API
                        fetchSessionDetail(sid, 0)
                          .then(d => { if (d.session) c.selectSession(d.session); })
                          .catch(() => {});
                      }}
                    />
                  </Suspense>
                ) : (
                  <GraphCanvas
                    nodes={c.visibleNodes}
                    edges={c.visibleEdges}
                    onSelect={c.handleGSel}
                    onInvestigate={c.handleInvestigate}
                    onInvestigateNeighbours={c.handleInvestigateNeighbours}
                    onHideNode={c.handleHideNode}
                    investigationNodes={c.investigationNodes}
                    displayFilterNodes={(() => {
                      const df = c.dfResult?.nodes ?? null;
                      const sr = c.searchResult?.nodes ?? null;
                      if (df && sr) return new Set([...df].filter(x => sr.has(x)));
                      return df || sr;
                    })()}
                    displayFilterEdges={(() => {
                      const df = c.dfResult?.edges ?? null;
                      const sr = c.searchResult?.edges ?? null;
                      if (df && sr) return new Set([...df].filter(x => sr.has(x)));
                      return df || sr;
                    })()}
                    selectedNodes={c.selNodes}
                    selectedEdge={c.selEdge}
                    pColors={c.pColors}
                    containerRef={graphContainerRef}
                    theme={settings.theme}
                    annotations={c.annotations}
                    onAddAnnotation={c.handleAddAnnotation}
                    onUpdateAnnotation={c.handleUpdateAnnotation}
                    onDeleteAnnotation={c.handleDeleteAnnotation}
                    onAddNodeAnnotation={c.handleAddNodeAnnotation}
                    onAddEdgeAnnotation={c.handleAddEdgeAnnotation}
                    onAddSyntheticNode={c.handleAddSyntheticNode}
                    onAddSyntheticEdge={c.handleAddSyntheticEdge}
                    onDeleteSynthetic={c.handleDeleteSynthetic}
                    onUnclusterSubnet={c.handleUnclusterSubnet}
                    onExpandCluster={c.handleExpandCluster}
                    onCreateManualCluster={c.handleCreateManualCluster}
                    onStartPathfind={c.startPathfind}
                    pathfindSource={c.pathfindSource}
                    onPathfindTarget={c.executePathfind}
                    onCancelPathfind={c.cancelPathfind}
                    onAnimate={(nodeIds) => {
                      const protos = toProtocolNames(c.enabledP, c.allProtocolKeysCountRef.current);
                      c.startAnimation(nodeIds, protos || undefined);
                    }}
                    labelThreshold={c.labelThreshold}
                    graphWeightMode={c.graphWeightMode}
                    edgeSizeMode={c.edgeSizeMode}
                    nodeColorMode={c.nodeColorMode}
                    edgeColorMode={c.edgeColorMode}
                    nodeColorRules={c.nodeColorRules}
                    edgeColorRules={c.edgeColorRules}
                    showEdgeDirection={c.showEdgeDirection}
                    queryHighlight={queryHighlight}
                    onClearQueryHighlight={() => setQueryHighlight(null)}
                    nodeEventSeverity={c.nodeEventSeverity}
                    edgeEventSeverity={c.edgeEventSeverity}
                    onFlagNode={(nodeId) => {
                      const node = c.graph?.nodes?.find(n => n.id === nodeId);
                      if (node) c.openFlagModal('node', node);
                    }}
                    onFlagEdge={(edgeId) => {
                      const edge = c.graph?.edges?.find(e => e.id === edgeId);
                      if (edge) c.openFlagModal('edge', edge);
                    }}
                  />
                )}

                {!c.animActive && (!c.graph.nodes || c.graph.nodes.length === 0) && (
                  <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', color: 'var(--txD)', fontSize: 12 }}>
                    No data matches filters
                  </div>
                )}

                {/* Cluster legend (only renders when clustering active, hidden in animation) */}
                {!c.animActive && (
                  <ClusterLegend
                    nodes={c.visibleNodes}
                    onSelect={c.handleGSel}
                    clusterNames={c.clusterNames}
                  />
                )}

                {/* Legend (hidden during animation — AnimationPane has its own) */}
                {!c.animActive && (
                  <div style={{
                    position: 'absolute', bottom: 10, left: 10, background: 'var(--bgP)',
                    border: '1px solid var(--bd)', borderRadius: 'var(--r)', padding: '6px 10px',
                    display: 'flex', flexWrap: 'wrap', gap: 7, maxWidth: 500, opacity: 0.9,
                  }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9 }}>
                      <span style={{ width: 10, height: 10, borderRadius: '50%', border: '1.5px solid var(--node-private-s)', display: 'inline-block', background: 'var(--node-private)' }} />
                      <span style={{ color: 'var(--txM)' }}>Private</span>
                    </span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9 }}>
                      <span style={{ width: 10, height: 10, borderRadius: '50%', border: '1.5px solid var(--node-external-s)', display: 'inline-block', background: 'var(--node-external)' }} />
                      <span style={{ color: 'var(--txM)' }}>External</span>
                    </span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9 }}>
                      <span style={{ width: 10, height: 10, borderRadius: 2, border: '1.5px solid var(--node-subnet-s)', display: 'inline-block', background: 'var(--node-subnet)' }} />
                      <span style={{ color: 'var(--txM)' }}>Subnet</span>
                    </span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9 }}>
                      <span style={{
                        width: 10, height: 10, display: 'inline-block',
                        background: 'var(--node-gateway)', border: '1.5px solid var(--node-gateway-s)',
                        transform: 'rotate(45deg)', borderRadius: 1,
                      }} />
                      <span style={{ color: 'var(--txM)' }}>Gateway</span>
                    </span>
                    <span style={{ color: 'var(--txD)', fontSize: 9 }}>|</span>
                    {(() => {
                      const seen = new Set();
                      const protos = [];
                      for (const key of c.enabledP) {
                        const parts = key.split('/');
                        const name = parts.length === 3 ? parts[2] : key;
                        if (!seen.has(name)) { seen.add(name); protos.push(name); }
                      }
                      return protos.slice(0, 8).map(p => (
                        <span key={p} style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 9 }}>
                          <span style={{ width: 10, height: 2.5, background: c.pColors[p] || '#64748b', display: 'inline-block', borderRadius: 1 }} />
                          <span style={{ color: 'var(--txM)' }}>{p}</span>
                        </span>
                      ));
                    })()}
                  </div>
                )}
              </div>

              {/* Timeline strip */}
              {c.timeline.length > 1 && workspace.showTimeline !== false && (
                <TimelineStrip
                  timeline={c.timeline}
                  timeRange={c.timeRange}
                  setTimeRange={c.setTimeRange}
                  bucketSec={c.bucketSec}
                  setBucketSec={c.setBucketSec}
                  width={gSize.width - 32}
                  animCursorTime={c.animActive ? c.currentEvent?.time : undefined}
                />
              )}
            </div>
            {/* END CENTER */}

            {/* RIGHT PANEL */}
            <div style={{ width: c.panelWidth, background: 'var(--bgP)', borderLeft: '1px solid var(--bd)', flexShrink: 0, overflow: 'hidden', position: 'relative', display: 'flex' }}>
              {/* Drag handle */}
              <div
                onPointerDown={c.handlePanelDragStart}
                style={{
                  position: 'absolute', left: 0, top: 0, bottom: 0, width: 4,
                  cursor: 'ew-resize', zIndex: 10, background: 'transparent', transition: 'background .15s',
                }}
                onMouseEnter={e => e.currentTarget.style.background = 'rgba(88,166,255,.25)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                title="Drag to resize panel"
              />
              <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
                {/* Back to animation breadcrumb (when detail is open during animation) */}
                {c.animActive && (c.selSession || c.selEdge || c.selNodes?.length > 0) && (
                  <div
                    onClick={c.clearSel}
                    style={{
                      fontSize: 10, color: '#58a6ff', cursor: 'pointer',
                      padding: '5px 14px', borderBottom: '1px solid var(--bd)',
                      fontFamily: 'var(--fn)', flexShrink: 0,
                      display: 'flex', alignItems: 'center', gap: 5,
                      background: 'rgba(88,166,255,0.06)',
                    }}
                  >
                    <span style={{ fontSize: 11 }}>←</span> Back to animation
                  </div>
                )}
                {/* Back / Forward navigation */}
                {(c.canGoBack || c.canGoForward) && (
                  <div style={{
                    display: 'flex', gap: 2, padding: '4px 8px',
                    borderBottom: '1px solid var(--bd)', flexShrink: 0,
                  }}>
                    <button className="btn" onClick={c.navBack} disabled={!c.canGoBack}
                      title="Go back"
                      style={{ fontSize: 11, padding: '1px 8px', opacity: c.canGoBack ? 1 : 0.3 }}>←</button>
                    <button className="btn" onClick={c.navForward} disabled={!c.canGoForward}
                      title="Go forward"
                      style={{ fontSize: 11, padding: '1px 8px', opacity: c.canGoForward ? 1 : 0.3 }}>→</button>
                  </div>
                )}
                <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
                  <AppRightPanel
                    c={c}
                    subgraphInfo={subgraphInfo}
                    queryHighlight={queryHighlight}
                    setQueryHighlight={setQueryHighlight}
                  />
                </div>
              </div>
            </div>
          </>
        )}
      </div>

      {/* Hidden file inputs (always in DOM so getElementById always finds them) */}
      <input id="pcap-re" type="file" accept=".pcap,.pcapng,.cap,.log,.csv" multiple onChange={c.handleFileInput} style={{ display: 'none' }} />
      <input id="meta-up" type="file" accept=".json" onChange={c.handleMetadataInput} style={{ display: 'none' }} />
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>

      {/* Schema negotiation dialog — shown when in-app upload triggers a schema mismatch */}
      {c.schemaNegotiation && (
        <SchemaDialog
          report={c.schemaNegotiation.report}
          stagingToken={c.schemaNegotiation.stagingToken}
          fileName={c.schemaNegotiation.fileName}
          onConfirm={c.handleSchemaConfirm}
          onCancel={c.handleSchemaCancel}
          loading={c.schemaConfirming}
        />
      )}

      {/* Type picker — shown when automatic format detection fails */}
      {c.typePicker && (
        <TypePickerDialog
          fileName={c.typePicker.files[0]?.name || 'file'}
          availableAdapters={c.typePicker.availableAdapters}
          onConfirm={c.handleTypePickerConfirm}
          onCancel={c.handleTypePickerCancel}
        />
      )}

      {/* Settings panel overlay */}
      {showSettings && (
        <SettingsPanel
          settings={settings}
          setSetting={setSetting}
          onClose={() => setShowSettings(false)}
        />
      )}

      {/* Event flag modal (v0.21.0) — opened via context menu / SessionDetail */}
      <EventFlagModal
        open={!!c.flaggingTarget}
        entity={c.flaggingTarget?.entity}
        entity_type={c.flaggingTarget?.entity_type}
        graph={c.graph}
        existingAnnotation={(() => {
          const tgt = c.flaggingTarget;
          if (!tgt) return null;
          const ann = (c.annotations || []).find(a =>
            (tgt.entity_type === 'node' && a.node_id === tgt.entity?.id) ||
            (tgt.entity_type === 'edge' && a.edge_id === tgt.entity?.id)
          );
          return ann?.label || null;
        })()}
        onConfirm={({ title, severity, description, includeAnnotation }) => {
          const tgt = c.flaggingTarget;
          if (!tgt) return;
          let annotation_snapshot = null;
          if (includeAnnotation) {
            const ann = (c.annotations || []).find(a =>
              (tgt.entity_type === 'node' && a.node_id === tgt.entity?.id) ||
              (tgt.entity_type === 'edge' && a.edge_id === tgt.entity?.id)
            );
            annotation_snapshot = ann?.label || null;
          }
          c.addEvent({
            entity: tgt.entity,
            entity_type: tgt.entity_type,
            title, severity, description,
            annotation_snapshot,
            graph: c.graph,
          });
          c.closeFlagModal();
        }}
        onClose={c.closeFlagModal}
      />
    </div>
    </FilterContext.Provider>
  );
}
