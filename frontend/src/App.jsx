/**
 * App.jsx — pure layout and routing.
 * All state/logic lives in useCapture(). This file only renders.
 */

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useCapture } from './hooks/useCapture';
import { fetchSessionDetail } from './api';
import { useSettings } from './hooks/useSettings';
import { FilterContext, toProtocolNames } from './FilterContext';
import logoFullData from './logoFullData.js';
import TopBar from './components/TopBar';
import FilterBar from './components/FilterBar';
import LeftPanel from './components/LeftPanel';
import GraphCanvas from './components/GraphCanvas';
import TimelineStrip from './components/TimelineStrip';
import StatsPanel from './components/StatsPanel';
import EdgeDetail from './components/EdgeDetail';
import NodeDetail from './components/NodeDetail';
import SessionsTable from './components/SessionsTable';
import SessionDetail from './components/SessionDetail';
import LogsPanel from './components/LogsPanel';
import TimelinePanel from './components/TimelinePanel';
import MultiSelectPanel from './components/MultiSelectPanel';
import ResearchPage from './components/ResearchPage';
import HelpPanel from './components/HelpPanel';
import SettingsPanel from './components/SettingsPanel';
import EventFlagModal from './components/EventFlagModal';
import AnalysisPage from './components/AnalysisPage';
import InvestigationPage from './components/InvestigationPage';
import VisualizePage from './components/VisualizePage';
import ClusterLegend from './components/ClusterLegend';
import ClusterDetail from './components/ClusterDetail';
import PathDetail from './components/PathDetail';
import QueryBuilder from './components/QueryBuilder';
import GraphOptionsPanel from './components/GraphOptionsPanel';
import AnimationPane from './components/AnimationPane';
import AlertsPanel from './components/AlertsPanel';

export default function App() {
  const c = useCapture();
  const { settings, setSetting } = useSettings();
  const [showSettings, setShowSettings] = useState(false);
  const [queryHighlight, setQueryHighlight] = useState(null);  // { nodes: Set, edges: Set }

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
  if (!c.loaded && c.rPanel !== 'visualize') {
    return (
      <div style={{ width: '100%', height: '100vh', background: 'var(--bg)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        {c.loading ? (
          <div style={{ textAlign: 'center' }}>
            <div style={{ width: 40, height: 40, border: '3px solid var(--bd)', borderTopColor: 'var(--ac)', borderRadius: '50%', animation: 'spin 0.8s linear infinite', margin: '0 auto 16px' }} />
            <div style={{ color: 'var(--txM)', fontSize: 13 }}>{c.loadMsg}</div>
          </div>
        ) : (
          <div
            onDrop={c.handleDrop} onDragOver={e => e.preventDefault()}
            onClick={() => document.getElementById('pcap-up').click()}
            style={{
              textAlign: 'center', padding: '64px 80px',
              border: '1.5px dashed rgba(88,166,255,.3)', borderRadius: 20,
              cursor: 'pointer', minWidth: 460,
              background: 'rgba(88,166,255,.02)',
            }}
          >
            <img src={logoFullData} alt="SwiftEye" style={{ height: 120, marginBottom: 40, opacity: 0.95 }} />
            <div style={{
              width: 64, height: 64, margin: '0 auto 24px', borderRadius: 16,
              background: 'rgba(88,166,255,.08)', border: '1px solid rgba(88,166,255,.25)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--ac)" strokeWidth="1.5">
                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12" />
              </svg>
            </div>
            <div style={{ fontSize: 16, color: 'var(--txM)', marginBottom: 10 }}>
              Drop <span style={{ color: 'var(--ac)' }}>capture files</span> here <span style={{ fontSize: 10, color: 'var(--txD)' }}>(pcap, Zeek logs, tshark CSV)</span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--txD)' }}>or click to browse · multiple files merge by timestamp · max 500MB each</div>
            {c.error && <div style={{ marginTop: 20, color: 'var(--acR)', fontSize: 13 }}>{c.error}</div>}
            <input id="pcap-up" type="file" accept=".pcap,.pcapng,.cap,.log,.csv" multiple onChange={c.handleFileInput} style={{ display: 'none' }} />
          </div>
        )}
        <div style={{ position: 'absolute', bottom: 24, display: 'flex', gap: 12 }}>
          <button className="btn" onClick={e => { e.stopPropagation(); c.switchPanel('visualize'); }}
            style={{ fontSize: 11, padding: '6px 16px', opacity: 0.7 }}>
            📂 Visualize custom data
          </button>
        </div>
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      </div>
    );
  }

  // ── Standalone Visualize (no capture needed) ─────────────────────
  if (!c.loaded && c.rPanel === 'visualize') {
    return (
      <div style={{ height: '100vh', display: 'flex', flexDirection: 'column', overflow: 'hidden', background: 'var(--bg)' }}>
        <div style={{ padding: '8px 16px', borderBottom: '1px solid var(--bd)', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          <button className="btn" onClick={() => c.switchPanel('stats')}
            style={{ fontSize: 10, padding: '3px 10px' }}>← Back to upload</button>
          <span style={{ fontSize: 12, color: 'var(--txD)' }}>No capture loaded — Visualize mode only</span>
        </div>
        <VisualizePage />
      </div>
    );
  }

  // ── Right panel content (non-full-width panels) ──────────────────
  // Back-to-path link shown on detail views when pathfindResult is active
  const pathBackLink = c.pathfindResult?.path_count > 0 ? (
    <div
      onClick={c.clearSel}
      style={{
        fontSize: 10, color: 'var(--ac)', cursor: 'pointer', padding: '6px 14px',
        borderBottom: '1px solid var(--bd)', fontFamily: 'var(--fn)',
        display: 'flex', alignItems: 'center', gap: 5,
      }}
    >
      <span style={{ fontSize: 9 }}>←</span> Back to Path Analysis
    </div>
  ) : null;

  let rightContent;
  if (c.selSession) {
    rightContent = (
      <SessionDetail
        session={c.selSession}
        collapseStates={c.collapseStatesRef}
        siblings={c.selSessionSiblings}
        onNavigate={c.selectSessionWithContext}
        onOpenSeqAck={id => { c.setSeqAckSessionId(id); c.switchPanel('research'); }}
        onBack={c.clearSel}
        pColors={c.pColors}
        annotations={c.annotations}
        onSaveNote={c.handleSaveNote}
        onFlagEvent={() => c.openFlagModal('session', c.selSession)}
        onTabChange={tab => {
          if (tab === 'charts' && c.panelWidth < 500) c.setPanelWidth(500);
        }}
      />
    );
  } else if (c.selEdge) {
    rightContent = (
      <>
        {pathBackLink}
        <EdgeDetail
          edge={c.selEdge} pColors={c.pColors}
          onClear={c.clearSel}
          nodes={c.visibleNodes}
          onSelectSession={c.selectSessionWithContext}
          annotations={c.annotations}
          onSaveNote={c.handleSaveNote}
          clusterNames={c.clusterNames}
          onFlagEvent={() => c.openFlagModal('edge', c.selEdge)}
        />
      </>
    );
  } else if (c.selNodes.length === 1) {
    // Check if the selected node is a cluster or subnet (both use ClusterDetail)
    const selNodeObj = (c.graph.nodes || []).find(n => n.id === c.selNodes[0]);
    if (selNodeObj?.is_cluster || selNodeObj?.is_subnet) {
      rightContent = (
        <ClusterDetail
          nodeId={c.selNodes[0]} nodes={c.graph.nodes || []} edges={c.graph.edges || []}
          sessions={c.sessions} pColors={c.pColors}
          onClear={c.clearSel}
          onSelectNode={c.selectNodePanel}
          onSelectEdge={e => c.handleGSel('edge', e, false)}
          onSelectSession={c.selectSession}
          clusterNames={c.clusterNames} onRenameCluster={c.renameCluster}
          rawGraph={c.rawGraph}
          annotations={c.annotations} onSaveNote={c.handleSaveNote}
        />
      );
    } else {
      // In clustered view, member nodes only exist in rawGraph — merge so NodeDetail can find them
      const detailNodes = c.clusterAlgo && c.rawGraph?.nodes
        ? [...(c.graph.nodes || []), ...c.rawGraph.nodes.filter(rn => !(c.graph.nodes || []).some(gn => gn.id === rn.id))]
        : (c.graph.nodes || []);
      const detailEdges = c.clusterAlgo && c.rawGraph?.edges
        ? [...(c.graph.edges || []), ...c.rawGraph.edges.filter(re => !(c.graph.edges || []).some(ge => ge.id === re.id))]
        : (c.graph.edges || []);
      rightContent = (
        <>
          {pathBackLink}
          <NodeDetail
            nodeId={c.selNodes[0]} nodes={detailNodes} edges={detailEdges}
            sessions={c.sessions} pColors={c.pColors}
            fullSessions={c.fullSessions}
            fullGraph={c.fullGraphRef}
            onClear={c.clearSel}
            onSelectNode={id => c.handleGSel('node', id, false)}
            onSelectEdge={e => c.handleGSel('edge', e, false)}
            onSelectSession={c.selectSession}
            pluginResults={c.pluginResults} uiSlots={c.pluginSlots}
            annotations={c.annotations}
            onSaveNote={c.handleSaveNote}
            onUpdateSynthetic={c.handleUpdateSyntheticNode}
            onAnimate={(nodeIds) => {
                  const protos = toProtocolNames(c.enabledP, c.allProtocolKeysCountRef.current);
                  c.startAnimation(nodeIds, protos || undefined);
                }}
            onFlagEvent={() => {
              const nObj = detailNodes.find(n => n.id === c.selNodes[0]);
              if (nObj) c.openFlagModal('node', nObj);
            }}
          />
        </>
      );
    }
  } else if (c.selNodes.length > 1) {
    rightContent = (
      <MultiSelectPanel
        selectedNodes={c.selNodes} nodes={c.graph.nodes || []} edges={c.graph.edges || []}
        sessions={c.sessions} pColors={c.pColors} onClear={c.clearSel}
        onSelectNode={c.selectNodePanel}
        onSelectEdge={e => c.handleGSel('edge', e, false)}
        onSelectSession={c.selectSession}
        onAnimate={(nodeIds) => {
                  const protos = toProtocolNames(c.enabledP, c.allProtocolKeysCountRef.current);
                  c.startAnimation(nodeIds, protos || undefined);
                }}
      />
    );
  } else if (c.pathfindResult) {
    rightContent = (
      <PathDetail
        pathResult={c.pathfindResult}
        onClear={c.exitInvestigation}
        onSelectNode={c.selectNodePanel}
        onSelectEdge={e => c.handleGSel('edge', e, false)}
        onRunPathfind={c.runPathfindFromPanel}
        pColors={c.pColors}
        allNodes={c.graph.nodes || []}
        allEdges={c.graph.edges || []}
      />
    );
  } else if (c.rPanel === 'sessions') {
    rightContent = <SessionsTable sessions={c.sessions} pColors={c.pColors} onSelect={c.selectSession} />;
  } else if (c.rPanel === 'logs') {
    rightContent = <LogsPanel />;
  } else if (c.rPanel === 'help') {
    rightContent = <HelpPanel />;
  } else if (c.rPanel === 'query') {
    rightContent = (
      <QueryBuilder
        loaded={c.loaded}
        onQueryResult={res => {
          const nodes = new Set((res.matched_nodes || []).map(m => m.id));
          const edges = new Set((res.matched_edges || []).map(m => m.id));
          setQueryHighlight(nodes.size || edges.size ? { nodes, edges } : null);
        }}
        onClearQuery={() => setQueryHighlight(null)}
        onSelectNode={id => c.handleGSel('node', id, false)}
        onSelectEdge={edgeId => {
          const e = (c.graph.edges || []).find(e => {
            if (e.id === edgeId || e.id?.startsWith(edgeId + '|')) return true;
            // D3 replaces source/target strings with node objects — extract .id
            const s = typeof e.source === 'object' ? e.source.id : e.source;
            const t = typeof e.target === 'object' ? e.target.id : e.target;
            return `${s}|${t}` === edgeId || `${t}|${s}` === edgeId;
          });
          if (e) c.handleGSel('edge', e, false);
        }}
      />
    );
  } else if (c.rPanel === 'graph-options') {
    rightContent = (
      <GraphOptionsPanel
        onClose={() => c.switchPanel('stats')}
        nodeColorMode={c.nodeColorMode} setNodeColorMode={c.setNodeColorMode}
        nodeColorRules={c.nodeColorRules} setNodeColorRules={c.setNodeColorRules}
        graphWeightMode={c.graphWeightMode} setGraphWeightMode={c.setGraphWeightMode}
        labelThreshold={c.labelThreshold} setLabelThreshold={c.setLabelThreshold}
        edgeColorMode={c.edgeColorMode} setEdgeColorMode={c.setEdgeColorMode}
        edgeColorRules={c.edgeColorRules} setEdgeColorRules={c.setEdgeColorRules}
        edgeSizeMode={c.edgeSizeMode} setEdgeSizeMode={c.setEdgeSizeMode}
        subnetG={c.subnetG} setSubnetG={c.setSubnetG} toggleSubnetG={c.toggleSubnetG}
        subnetPrefix={c.subnetPrefix} setSubnetPrefix={c.setSubnetPrefix}
        mergeByMac={c.mergeByMac} setMergeByMac={c.setMergeByMac}
        includeIPv6={c.includeIPv6} setIncludeIPv6={c.setIncludeIPv6}
        showHostnames={c.showHostnames} setShowHostnames={c.setShowHostnames}
        excludeBroadcasts={c.excludeBroadcasts} setExcludeBroadcasts={c.setExcludeBroadcasts}
        clusterAlgo={c.clusterAlgo} setClusterAlgo={c.setClusterAlgo}
        clusterResolution={c.clusterResolution} setClusterResolution={c.setClusterResolution}
        visibleNodes={c.visibleNodes}
      />
    );
  } else {
    rightContent = (
      <StatsPanel
        stats={c.stats} pColors={c.pColors}
        onSelectNode={c.selectNodePanel}
        pluginResults={c.pluginResults} uiSlots={c.pluginSlots}
        subgraphInfo={subgraphInfo}
      />
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
        onLogoClick={() => { c.clearAll(); if (c.animActive) c.stopAnimation(); }}
      />
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
        />

        {c.rPanel === 'research' ? (
          /* RESEARCH PAGE — full width, replaces graph + right panel */
          <ResearchPage
            investigatedIp={c.investigatedIp}
            seqAckSessionId={c.seqAckSessionId}
            searchIp={/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(c.search.trim()) ? c.search.trim() : ''}
            availableIps={c.availableIps}
            timeline={c.timeline}
            timeRange={c.timeRange} setTimeRange={c.setTimeRange}
            bucketSec={c.bucketSec} setBucketSec={c.setBucketSec}
          />
        ) : c.rPanel === 'timeline' ? (
          /* TIMELINE PAGE — full width, replaces graph + right panel */
          <TimelinePanel
            sessions={c.sessions}
            timeline={c.timeline}
            timeRange={c.timeRange} setTimeRange={c.setTimeRange}
            bucketSec={c.bucketSec} setBucketSec={c.setBucketSec}
          />
        ) : c.rPanel === 'analysis' ? (
          /* ANALYSIS PAGE — full width, replaces graph + right panel */
          <AnalysisPage
            nodes={c.visibleNodes}
            edges={c.visibleEdges}
            sessions={c.sessions}
            pColors={c.pColors}
            onSelectNode={c.selectNodePanel}
          />
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
            onSelectEntity={(entity_type, entity_id) => {
              if (!entity_type || !entity_id) return;
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
              {c.timeline.length > 1 && (
                <TimelineStrip
                  timeline={c.timeline}
                  timeRange={c.timeRange}
                  setTimeRange={c.setTimeRange}
                  bucketSec={c.bucketSec}
                  setBucketSec={c.setBucketSec}
                  width={gSize.width - 32}
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
                <div style={{ flex: 1, overflow: 'hidden' }}>
                  {rightContent}
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
