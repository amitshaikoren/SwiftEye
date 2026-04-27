import { useRef, useEffect } from 'react';

export default function useGraphViewSync({
  renRef, rafRef,
  annotations, selectedNodes, selectedEdge, pColors,
  onSelect, onInvestigate, onInvestigateNeighbours, onClearQueryHighlight,
  pathfindSource, onPathfindTarget,
  labelThreshold, edgeSizeMode, nodeColorMode, edgeColorMode,
  nodeColorRules, edgeColorRules, showEdgeDirection,
  nodeWeightField, nodeWeightScale, edgeWeightField, edgeWeightScale,
  investigationNodes, displayFilterNodes, displayFilterEdges,
  queryHighlight, theme,
}) {
  const selNRef = useRef(new Set());
  const selERef = useRef(null);
  const pcRef = useRef(pColors);
  const onSelRef = useRef(onSelect);
  const onInvRef = useRef(onInvestigate);
  const onInvNbRef = useRef(onInvestigateNeighbours);
  const onClearQHRef = useRef(onClearQueryHighlight);
  const labelThreshRef = useRef(labelThreshold);
  const edgeSizeModeRef = useRef(edgeSizeMode);
  const nodeColorModeRef = useRef(nodeColorMode);
  const edgeColorModeRef = useRef(edgeColorMode);
  const nodeColorRulesRef = useRef(nodeColorRules);
  const edgeColorRulesRef = useRef(edgeColorRules);
  const showEdgeDirectionRef = useRef(showEdgeDirection);
  const nodeWeightFieldRef = useRef(nodeWeightField);
  const nodeWeightScaleRef = useRef(nodeWeightScale);
  const edgeWeightFieldRef = useRef(edgeWeightField);
  const edgeWeightScaleRef = useRef(edgeWeightScale);
  const invNodesRef = useRef(investigationNodes);
  const dfNodesRef = useRef(displayFilterNodes);
  const dfEdgesRef = useRef(displayFilterEdges);
  const qhRef = useRef(queryHighlight);
  const annotationsRef = useRef(annotations);
  const pathfindSourceRef = useRef(pathfindSource);
  const onPathfindTargetRef = useRef(onPathfindTarget);

  function triggerRender() {
    if (renRef.current) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = requestAnimationFrame(renRef.current);
    }
  }

  // Simple prop-to-ref syncs (no render trigger)
  useEffect(() => { annotationsRef.current = annotations; }, [annotations]);
  useEffect(() => { selNRef.current = new Set(selectedNodes); }, [selectedNodes]);
  useEffect(() => { selERef.current = selectedEdge; }, [selectedEdge]);
  useEffect(() => { pcRef.current = pColors; }, [pColors]);
  useEffect(() => { onSelRef.current = onSelect; }, [onSelect]);
  useEffect(() => { onInvRef.current = onInvestigate; }, [onInvestigate]);
  useEffect(() => { onInvNbRef.current = onInvestigateNeighbours; }, [onInvestigateNeighbours]);
  useEffect(() => { onClearQHRef.current = onClearQueryHighlight; }, [onClearQueryHighlight]);
  useEffect(() => { labelThreshRef.current = labelThreshold; }, [labelThreshold]);
  useEffect(() => { pathfindSourceRef.current = pathfindSource; }, [pathfindSource]);
  useEffect(() => { onPathfindTargetRef.current = onPathfindTarget; }, [onPathfindTarget]);

  // Prop-to-ref syncs with render trigger
  useEffect(() => { edgeSizeModeRef.current      = edgeSizeMode;      triggerRender(); }, [edgeSizeMode]);
  useEffect(() => { nodeColorModeRef.current     = nodeColorMode;     triggerRender(); }, [nodeColorMode]);
  useEffect(() => { edgeColorModeRef.current     = edgeColorMode;     triggerRender(); }, [edgeColorMode]);
  useEffect(() => { nodeColorRulesRef.current    = nodeColorRules;    triggerRender(); }, [nodeColorRules]);
  useEffect(() => { edgeColorRulesRef.current    = edgeColorRules;    triggerRender(); }, [edgeColorRules]);
  useEffect(() => { showEdgeDirectionRef.current = showEdgeDirection; triggerRender(); }, [showEdgeDirection]);
  useEffect(() => { edgeWeightFieldRef.current   = edgeWeightField;   triggerRender(); }, [edgeWeightField]);
  useEffect(() => { edgeWeightScaleRef.current   = edgeWeightScale;   triggerRender(); }, [edgeWeightScale]);

  useEffect(() => {
    invNodesRef.current = investigationNodes;
    triggerRender();
  }, [investigationNodes]);

  useEffect(() => {
    dfNodesRef.current = displayFilterNodes;
    dfEdgesRef.current = displayFilterEdges;
    triggerRender();
  }, [displayFilterNodes, displayFilterEdges]);

  useEffect(() => {
    qhRef.current = queryHighlight;
    triggerRender();
  }, [queryHighlight]);

  // Re-render on selection change
  useEffect(() => { triggerRender(); }, [selectedNodes, selectedEdge]);

  // Re-render on theme change
  useEffect(() => {
    if (!renRef.current) return;
    const t = setTimeout(() => triggerRender(), 20);
    return () => clearTimeout(t);
  }, [theme]);

  // Re-render when label threshold changes
  useEffect(() => { triggerRender(); }, [labelThreshold]);

  return {
    selNRef, selERef, pcRef,
    onSelRef, onInvRef, onInvNbRef, onClearQHRef,
    labelThreshRef, edgeSizeModeRef, nodeColorModeRef, edgeColorModeRef,
    nodeColorRulesRef, edgeColorRulesRef, showEdgeDirectionRef,
    nodeWeightFieldRef, nodeWeightScaleRef, edgeWeightFieldRef, edgeWeightScaleRef,
    invNodesRef, dfNodesRef, dfEdgesRef, qhRef,
    annotationsRef, pathfindSourceRef, onPathfindTargetRef,
  };
}
