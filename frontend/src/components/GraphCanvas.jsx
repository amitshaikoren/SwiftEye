/**
 * GraphCanvas — D3 force-directed network graph on HTML canvas.
 *
 * Coordinator component: calls domain hooks and renders sub-components.
 * All heavy logic lives in graph/hooks/ and graph/components/.
 *
 * CRITICAL BUG FIXES applied:
 *   1. Canvas resize: reads parentElement.clientWidth/Height directly in the
 *      render loop every frame, eliminating the black-bar-on-resize issue
 *      caused by ResizeObserver lag.
 *   2. Node dragging: uses pointer events + setPointerCapture + zoom filter
 *      toggling so drag and zoom never conflict.
 */

import React, { useRef, useState } from 'react';
import * as d3 from 'd3';

import useGraphSim from './graph/hooks/useGraphSim';
import useGraphViewSync from './graph/hooks/useGraphViewSync';
import useGraphInteraction from './graph/hooks/useGraphInteraction';
import useGraphResizePolling from './graph/hooks/useGraphResizePolling';

import GraphContextMenu from './graph/components/GraphContextMenu';
import GraphAnnotationOverlay from './graph/components/GraphAnnotationOverlay';
import GraphEventDots from './graph/components/GraphEventDots';
import SyntheticNodeForm from './graph/components/SyntheticNodeForm';
import SyntheticEdgeForm from './graph/components/SyntheticEdgeForm';
import GraphLegend from './graph/GraphLegend';

export default function GraphCanvas({
  nodes, edges, onSelect, onInvestigate, onInvestigateNeighbours, onHideNode, investigationNodes,
  displayFilterNodes, displayFilterEdges,
  selectedNodes, selectedEdge, pColors,
  containerRef, theme,
  annotations = [], onAddAnnotation, onUpdateAnnotation, onDeleteAnnotation,
  onAddNodeAnnotation, onAddEdgeAnnotation,
  nodeEventSeverity, edgeEventSeverity,
  onFlagNode, onFlagEdge,
  onAddSyntheticNode, onAddSyntheticEdge, onDeleteSynthetic, onUnclusterSubnet,
  onExpandCluster, onRelayout, onCreateManualCluster,
  onStartPathfind, pathfindSource, onPathfindTarget, onCancelPathfind, onAnimate,
  labelThreshold = 0,
  graphWeightMode = 'bytes',
  edgeSizeMode = 'bytes',
  nodeColorMode = 'address',
  edgeColorMode = 'protocol',
  nodeColorRules = [],
  edgeColorRules = [],
  showEdgeDirection = false,
  queryHighlight = null,
  onClearQueryHighlight,
}) {
  // Shared refs — declared here so all hooks share the same ref objects
  const cRef = useRef(null);
  const tRef = useRef(d3.zoomIdentity);
  const renRef = useRef(null);
  const rafRef = useRef(null);
  const hRef = useRef(null);

  // React state — declared here since interaction hook needs the setters
  const [ctxMenu, setCtxMenu] = useState(null);
  const [lasso, setLasso] = useState(null);
  const [transformVersion, setTransformVersion] = useState(0);
  const [showSyntheticNodeForm, setShowSyntheticNodeForm] = useState(false);
  const [showSyntheticEdgeForm, setShowSyntheticEdgeForm] = useState(false);
  const [synEdgeSrc, setSynEdgeSrc] = useState('');
  const [editingAnn, setEditingAnn] = useState(null);

  // Hook 1: Visual mode ref syncing (declared first so refs exist for sim)
  const {
    selNRef, selERef, pcRef,
    onSelRef, onInvRef, onInvNbRef, onClearQHRef,
    labelThreshRef, edgeSizeModeRef, nodeColorModeRef, edgeColorModeRef,
    nodeColorRulesRef, edgeColorRulesRef,
    invNodesRef, dfNodesRef, dfEdgesRef, qhRef,
    annotationsRef, pathfindSourceRef, onPathfindTargetRef,
  } = useGraphViewSync({
    renRef, rafRef,
    annotations, selectedNodes, selectedEdge, pColors,
    onSelect, onInvestigate, onInvestigateNeighbours, onClearQueryHighlight,
    pathfindSource, onPathfindTarget,
    labelThreshold, edgeSizeMode, nodeColorMode, edgeColorMode,
    nodeColorRules, edgeColorRules, showEdgeDirection,
    investigationNodes, displayFilterNodes, displayFilterEdges,
    queryHighlight, theme,
  });

  // Hook 2: Simulation + render loop
  const { simRef, nRef, eRef, gRRef, doRelayout, doExportHTML } =
    useGraphSim({
      nodes, edges, cRef, containerRef, graphWeightMode, tRef,
      renRef, rafRef, hRef,
      selNRef, selERef, pcRef, invNodesRef, dfNodesRef, dfEdgesRef, qhRef,
      labelThreshRef, edgeSizeModeRef, nodeColorModeRef, edgeColorModeRef,
      nodeColorRulesRef, edgeColorRulesRef, showEdgeDirectionRef,
    });

  // Hook 3: Resize polling
  useGraphResizePolling({ containerRef, simRef, renRef, rafRef });

  // Hook 4: Interaction (pointer events, zoom, drag, lasso, ctx menu)
  useGraphInteraction({
    cRef, simRef, nRef, eRef, tRef, gRRef, renRef, rafRef, hRef,
    selNRef, pathfindSourceRef, onPathfindTargetRef,
    onSelRef, qhRef, onClearQHRef,
    setCtxMenu, setLasso, setTransformVersion,
  });

  return (
    <div style={{ width: '100%', height: '100%', position: 'relative' }}>
      <canvas ref={cRef} style={{ width: '100%', height: '100%', display: 'block', cursor: pathfindSource ? 'crosshair' : undefined }} />

      {/* Export HTML button */}
      <button onClick={doExportHTML} title="Export interactive graph as self-contained HTML"
        style={{
          position: 'absolute', bottom: 84, right: 12, zIndex: 10,
          display: 'flex', alignItems: 'center', gap: 5,
          background: 'rgba(14,17,23,.85)', border: '1px solid var(--bdL)',
          borderRadius: 6, padding: '5px 10px', fontSize: 10,
          color: 'var(--txM)', cursor: 'pointer', fontFamily: 'var(--fn)',
        }}>
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
        </svg>
        Export HTML
      </button>

      {/* Relayout button */}
      <button onClick={doRelayout} title="Reset layout — unpins all nodes and re-runs the force simulation"
        style={{
          position: 'absolute', bottom: 48, right: 12, zIndex: 10,
          display: 'flex', alignItems: 'center', gap: 5,
          background: 'rgba(14,17,23,.85)', border: '1px solid var(--bdL)',
          borderRadius: 6, padding: '5px 10px', fontSize: 10,
          color: 'var(--txM)', cursor: 'pointer', fontFamily: 'var(--fn)',
        }}>
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polyline points="1 4 1 10 7 10"/><polyline points="23 20 23 14 17 14"/>
          <path d="M20.49 9A9 9 0 005.64 5.64L1 10m22 4l-4.64 4.36A9 9 0 013.51 15"/>
        </svg>
        Relayout
      </button>

      {/* Color legend overlay */}
      <GraphLegend nodeColorMode={nodeColorMode} edgeColorMode={edgeColorMode} />

      {/* Lasso selection overlay */}
      {lasso && lasso.points?.length >= 2 && (
        <svg style={{
          position: 'absolute', inset: 0, width: '100%', height: '100%',
          pointerEvents: 'none', zIndex: 5, overflow: 'visible',
        }}>
          <polygon
            points={lasso.points.map(p => `${p.x},${p.y}`).join(' ')}
            fill="rgba(88,166,255,0.07)"
            stroke="var(--ac)"
            strokeWidth="1.5"
            strokeDasharray="5,3"
            strokeLinejoin="round"
          />
        </svg>
      )}

      {ctxMenu && (
        <GraphContextMenu
          ctxMenu={ctxMenu} setCtxMenu={setCtxMenu} cRef={cRef} eRef={eRef} selNRef={selNRef}
          onSelRef={onSelRef} onInvRef={onInvRef} onInvNbRef={onInvNbRef}
          onAnimate={onAnimate} onFlagNode={onFlagNode} onFlagEdge={onFlagEdge} onHideNode={onHideNode}
          onDeleteSynthetic={onDeleteSynthetic} onStartPathfind={onStartPathfind}
          onExpandCluster={onExpandCluster} onUnclusterSubnet={onUnclusterSubnet} onCreateManualCluster={onCreateManualCluster}
          onAddNodeAnnotation={onAddNodeAnnotation} onAddEdgeAnnotation={onAddEdgeAnnotation} onAddAnnotation={onAddAnnotation}
          setShowSyntheticNodeForm={setShowSyntheticNodeForm} setShowSyntheticEdgeForm={setShowSyntheticEdgeForm} setSynEdgeSrc={setSynEdgeSrc}
        />
      )}

      {/* Synthetic node/edge creation forms (modal overlays) */}
      {showSyntheticNodeForm && (
        <>
          <div style={{ position: 'absolute', inset: 0, zIndex: 199, background: 'rgba(0,0,0,.45)' }}
            onClick={() => setShowSyntheticNodeForm(false)} />
          <SyntheticNodeForm onClose={() => setShowSyntheticNodeForm(false)} onAddSyntheticNode={onAddSyntheticNode} />
        </>
      )}
      {showSyntheticEdgeForm && (
        <>
          <div style={{ position: 'absolute', inset: 0, zIndex: 199, background: 'rgba(0,0,0,.45)' }}
            onClick={() => setShowSyntheticEdgeForm(false)} />
          <SyntheticEdgeForm onClose={() => setShowSyntheticEdgeForm(false)} onAddSyntheticEdge={onAddSyntheticEdge} synEdgeSrc={synEdgeSrc} nRef={nRef} />
        </>
      )}

      <GraphEventDots
        nodeEventSeverity={nodeEventSeverity} edgeEventSeverity={edgeEventSeverity}
        nRef={nRef} eRef={eRef} tRef={tRef} gRRef={gRRef} transformVersion={transformVersion}
      />

      <GraphAnnotationOverlay
        annotations={annotations} tRef={tRef} nRef={nRef} eRef={eRef}
        transformVersion={transformVersion} editingAnn={editingAnn} setEditingAnn={setEditingAnn}
        onUpdateAnnotation={onUpdateAnnotation} onDeleteAnnotation={onDeleteAnnotation}
      />
    </div>
  );
}
