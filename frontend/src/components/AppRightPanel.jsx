/**
 * AppRightPanel.jsx — right-panel content assembly for App.jsx.
 *
 * Selects and renders the correct detail/panel component based on the
 * current selection state in `c` (useCapture output).
 *
 * Props: c, subgraphInfo, queryHighlight, setQueryHighlight
 */

import React, { useState, useEffect } from 'react';
import { toProtocolNames } from '../FilterContext';
import SessionDetail from './SessionDetail';
import EdgeDetail from './EdgeDetail';
import NodeDetail from './NodeDetail';
import SessionsTable from './SessionsTable';
import LogsPanel from './LogsPanel';
import HelpPanel from './HelpPanel';
import QueryBuilder from './QueryBuilder';
import RecipePanel from './query/RecipePanel';
import GroupsPanel from './query/GroupsPanel';
import GuidePanel from './GuidePanel';
import GraphOptionsPanel from './GraphOptionsPanel';
import StatsPanel from './StatsPanel';
import ClusterDetail from './ClusterDetail';
import PathDetail from './PathDetail';
import MultiSelectPanel from './MultiSelectPanel';

let nextStepIdCounter = 1;
function newStepId() { return `s${Date.now().toString(36)}${(nextStepIdCounter++).toString(36)}`; }

export default function AppRightPanel({ c, subgraphInfo, queryHighlight, setQueryHighlight, annotationStore, onAnnotationsChange, appendStepRef, removeStepByIdRef, onRecipeChangeRef }) {
  // Recipe state hoisted here so it survives switching right panels (stats / node detail / etc.).
  // Intentionally not persisted — fresh load (reload or server restart) starts with an empty recipe.
  const [recipeSteps, setRecipeSteps] = useState([]);
  const [querySubTab, setQuerySubTab] = useState('query'); // 'query' | 'guide' | 'groups'
  const [groupsVersion, setGroupsVersion] = useState(0);

  function appendStep(draft) {
    setRecipeSteps(prev => [...prev, { id: newStepId(), enabled: true, ...draft }]);
  }

  // Expose append/remove to parent (for legend-as-filter wiring).
  if (appendStepRef) appendStepRef.current = appendStep;
  if (removeStepByIdRef) removeStepByIdRef.current = (id) => setRecipeSteps(prev => prev.filter(s => s.id !== id));

  // Notify parent when recipe changes (so legend toggles can stay in sync if user manually removes a step).
  useEffect(() => {
    onRecipeChangeRef?.current?.(recipeSteps);
  }, [recipeSteps, onRecipeChangeRef]);

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
    const tabStyle = active => ({
      fontSize: 11, padding: '6px 14px', cursor: 'pointer', fontFamily: 'var(--fd)',
      background: 'transparent', border: 'none',
      color: active ? 'var(--ac)' : 'var(--txD)',
      borderBottom: `2px solid ${active ? 'var(--ac)' : 'transparent'}`,
      fontWeight: active ? 600 : 400,
    });
    return (
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
        <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--bd)', background: 'var(--bg)', flexShrink: 0 }}>
          <button onClick={() => setQuerySubTab('query')} style={tabStyle(querySubTab === 'query')}>Query</button>
          <button onClick={() => setQuerySubTab('groups')} style={tabStyle(querySubTab === 'groups')}>Groups</button>
          <button onClick={() => setQuerySubTab('guide')} style={tabStyle(querySubTab === 'guide')}>Guide</button>
        </div>
        <div style={{ flex: 1, minHeight: 0, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          {/* All three sub-panels stay mounted — only visibility toggles. Keeps
              QueryBuilder's local form state intact on tab switch and lets the
              RecipePanel debounced pipeline run complete even while the user is
              viewing Groups (otherwise unmount-on-switch cancels the run and the
              group is never recorded). */}
          <div style={{ display: querySubTab === 'query' ? 'flex' : 'none', flexDirection: 'column', flex: 1, minHeight: 0 }}>
            <QueryBuilder
              loaded={c.loaded}
              onQueryResult={onQueryResultLegacy}
              onClearQuery={() => setQueryHighlight(null)}
              onAddStep={appendStep}
              groupsRefreshKey={groupsVersion}
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
              onHiddenChange={c.setHiddenNodes}
              onHiddenEdgesChange={c.setHiddenEdges}
              annotationStore={annotationStore}
              onAnnotationsChange={onAnnotationsChange}
              onRunComplete={() => setGroupsVersion(v => v + 1)}
              groupsRefreshKey={groupsVersion}
            />
          </div>
          <div style={{ display: querySubTab === 'guide' ? 'flex' : 'none', flex: 1, minHeight: 0, overflowY: 'auto', flexDirection: 'column' }}>
            <GuidePanel loaded={c.loaded} />
          </div>
          <div style={{ display: querySubTab === 'groups' ? 'flex' : 'none', flex: 1, minHeight: 0, overflowY: 'auto', flexDirection: 'column' }}>
            <GroupsPanel
              loaded={c.loaded}
              refreshKey={groupsVersion}
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
          </div>
        </div>
      </div>
    );
  }

  if (c.rPanel === 'graph-options') {
    return (
      <GraphOptionsPanel
        onClose={() => c.switchPanel('stats')}
        layoutMode={c.layoutMode} setLayoutMode={c.setLayoutMode}
        layoutFocusNodeId={c.layoutFocusNodeId}
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
        forceParams={c.forceParams} setForceParams={c.setForceParams}
        frozen={c.frozen} setFrozen={c.setFrozen}
        onReheat={c.incReheat}
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
