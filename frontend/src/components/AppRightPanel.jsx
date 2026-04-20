/**
 * AppRightPanel.jsx — right-panel content assembly for App.jsx.
 *
 * Selects and renders the correct detail/panel component based on the
 * current selection state in `c` (useCapture output).
 *
 * Props: c, subgraphInfo, queryHighlight, setQueryHighlight
 */

import React, { useEffect, useState } from 'react';
import { toProtocolNames } from '../FilterContext';
import SessionDetail from './SessionDetail';
import EdgeDetail from './EdgeDetail';
import NodeDetail from './NodeDetail';
import SessionsTable from './SessionsTable';
import LogsPanel from './LogsPanel';
import HelpPanel from './HelpPanel';
import QueryBuilder from './QueryBuilder';
import RecipePanel from './query/RecipePanel';
import GraphOptionsPanel from './GraphOptionsPanel';
import StatsPanel from './StatsPanel';
import ClusterDetail from './ClusterDetail';
import PathDetail from './PathDetail';
import MultiSelectPanel from './MultiSelectPanel';

const RECIPE_LS_KEY = 'swifteye.queryRecipe';
let nextStepIdCounter = 1;
function newStepId() { return `s${Date.now().toString(36)}${(nextStepIdCounter++).toString(36)}`; }

export default function AppRightPanel({ c, subgraphInfo, queryHighlight, setQueryHighlight }) {
  // Recipe state hoisted here so it survives switching right panels (stats / node detail / etc.)
  const [recipeSteps, setRecipeSteps] = useState(() => {
    try {
      const raw = localStorage.getItem(RECIPE_LS_KEY);
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch { return []; }
  });

  useEffect(() => {
    try { localStorage.setItem(RECIPE_LS_KEY, JSON.stringify(recipeSteps)); } catch {}
  }, [recipeSteps]);

  function appendStep(draft) {
    setRecipeSteps(prev => [...prev, { id: newStepId(), enabled: true, ...draft }]);
  }

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


  if (c.selSession) {
    return (
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
  }

  if (c.selEdge) {
    return (
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
  }

  if (c.selNodes.length === 1) {
    const selNodeObj = (c.graph.nodes || []).find(n => n.id === c.selNodes[0]);
    if (selNodeObj?.is_cluster || selNodeObj?.is_subnet) {
      return (
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
    }
    // In clustered view, member nodes only exist in rawGraph — merge so NodeDetail can find them
    const detailNodes = c.clusterAlgo && c.rawGraph?.nodes
      ? [...(c.graph.nodes || []), ...c.rawGraph.nodes.filter(rn => !(c.graph.nodes || []).some(gn => gn.id === rn.id))]
      : (c.graph.nodes || []);
    const detailEdges = c.clusterAlgo && c.rawGraph?.edges
      ? [...(c.graph.edges || []), ...c.rawGraph.edges.filter(re => !(c.graph.edges || []).some(ge => ge.id === re.id))]
      : (c.graph.edges || []);
    return (
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

  if (c.selNodes.length > 1) {
    return (
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
  }

  if (c.pathfindResult) {
    return (
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
  }

  if (c.rPanel === 'sessions') {
    return <SessionsTable sessions={c.sessions} pColors={c.pColors} onSelect={c.selectSession} />;
  }
  if (c.rPanel === 'logs') return <LogsPanel />;
  if (c.rPanel === 'help') return <HelpPanel />;

  if (c.rPanel === 'query') {
    const onQueryResultLegacy = res => {
      const nodes = new Set((res.matched_nodes || []).map(m => m.id));
      const edges = new Set((res.matched_edges || []).map(m => m.id));
      setQueryHighlight(nodes.size || edges.size ? { nodes, edges } : null);
    };
    return (
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0, overflowY: 'auto' }}>
        <QueryBuilder
          loaded={c.loaded}
          onQueryResult={onQueryResultLegacy}
          onClearQuery={() => setQueryHighlight(null)}
          onAddStep={appendStep}
          onSelectNode={id => c.handleGSel('node', id, false)}
          onSelectEdge={edgeId => {
            const e = (c.graph.edges || []).find(e => {
              if (e.id === edgeId || e.id?.startsWith(edgeId + '|')) return true;
              const s = typeof e.source === 'object' ? e.source.id : e.source;
              const t = typeof e.target === 'object' ? e.target.id : e.target;
              return `${s}|${t}` === edgeId || `${t}|${s}` === edgeId;
            });
            if (e) c.handleGSel('edge', e, false);
          }}
        />
        <RecipePanel
          loaded={c.loaded}
          steps={recipeSteps}
          onStepsChange={setRecipeSteps}
          onHighlightChange={setQueryHighlight}
        />
      </div>
    );
  }

  if (c.rPanel === 'graph-options') {
    return (
      <GraphOptionsPanel
        onClose={() => c.switchPanel('stats')}
        nodeColorMode={c.nodeColorMode} setNodeColorMode={c.setNodeColorMode}
        nodeColorRules={c.nodeColorRules} setNodeColorRules={c.setNodeColorRules}
        graphWeightMode={c.graphWeightMode} setGraphWeightMode={c.setGraphWeightMode}
        labelThreshold={c.labelThreshold} setLabelThreshold={c.setLabelThreshold}
        edgeColorMode={c.edgeColorMode} setEdgeColorMode={c.setEdgeColorMode}
        edgeColorRules={c.edgeColorRules} setEdgeColorRules={c.setEdgeColorRules}
        edgeSizeMode={c.edgeSizeMode} setEdgeSizeMode={c.setEdgeSizeMode}
        showEdgeDirection={c.showEdgeDirection} setShowEdgeDirection={c.setShowEdgeDirection}
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
  }

  return (
    <StatsPanel
      stats={c.stats} pColors={c.pColors}
      onSelectNode={c.selectNodePanel}
      pluginResults={c.pluginResults} uiSlots={c.pluginSlots}
      subgraphInfo={subgraphInfo}
    />
  );
}
