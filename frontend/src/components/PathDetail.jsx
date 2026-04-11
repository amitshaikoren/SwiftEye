import React, { useState } from 'react';
import Tag from './Tag';
import { fB } from '../utils';

/**
 * PathDetail — right-panel view for pathfinding results.
 *
 * Shows:
 *  - Source/target IP inputs (pre-filled from graph pick)
 *  - Directed/undirected toggle
 *  - Hop layers with collapsible per-node edges
 *  - Summary stats (path count, node count, edge count)
 *
 * Clicking a node → onSelectNode (opens NodeDetail, with back button)
 * Clicking an edge → onSelectEdge (opens EdgeDetail, with back button)
 */

export default function PathDetail({
  pathResult,       // {source, target, directed, path_count, hop_layers, edges, nodes}
  onClear,          // exit pathfinding entirely
  onSelectNode,     // (nodeId) => open NodeDetail
  onSelectEdge,     // (edgeObj) => open EdgeDetail
  onRunPathfind,    // (source, target, {directed}) => re-run with new params
  pColors,
  allNodes,         // graph.nodes for looking up edge objects
  allEdges,         // graph.edges for looking up edge objects
}) {
  const [srcInput, setSrcInput] = useState(pathResult?.source || '');
  const [tgtInput, setTgtInput] = useState(pathResult?.target || '');
  const [directed, setDirected] = useState(pathResult?.directed || false);
  const [expandedNodes, setExpandedNodes] = useState(new Set());

  // Sync inputs when pathResult changes
  React.useEffect(() => {
    if (pathResult?.source) setSrcInput(pathResult.source);
    if (pathResult?.target) setTgtInput(pathResult.target);
    if (pathResult?.directed != null) setDirected(pathResult.directed);
    setExpandedNodes(new Set());
  }, [pathResult?.source, pathResult?.target, pathResult?.directed]);

  const hopLayers = pathResult?.hop_layers || {};
  const pathEdges = pathResult?.edges || [];
  const pathCount = pathResult?.path_count || 0;
  const nodeCount = pathResult?.nodes?.length || 0;
  const maxHop = Object.keys(hopLayers).length - 1;

  // Build a lookup: nodeId -> list of edges involving that node
  const nodeEdgeMap = {};
  for (const e of pathEdges) {
    if (!nodeEdgeMap[e.source]) nodeEdgeMap[e.source] = [];
    if (!nodeEdgeMap[e.target]) nodeEdgeMap[e.target] = [];
    nodeEdgeMap[e.source].push(e);
    if (e.source !== e.target) nodeEdgeMap[e.target].push(e);
  }

  function toggleNode(nodeId) {
    setExpandedNodes(prev => {
      const next = new Set(prev);
      if (next.has(nodeId)) next.delete(nodeId);
      else next.add(nodeId);
      return next;
    });
  }

  // Find the matching edge object from allEdges for navigation
  function findGraphEdge(src, tgt) {
    if (!allEdges) return null;
    return allEdges.find(e => {
      const es = typeof e.source === 'object' ? e.source.id : e.source;
      const et = typeof e.target === 'object' ? e.target.id : e.target;
      return (es === src && et === tgt) || (es === tgt && et === src);
    });
  }

  function handleRun() {
    const s = srcInput.trim();
    const t = tgtInput.trim();
    if (s && t && s !== t && onRunPathfind) {
      onRunPathfind(s, t, { directed });
    }
  }

  function handleKeyDown(e) {
    if (e.key === 'Enter') handleRun();
  }

  const inputStyle = {
    flex: 1, background: 'var(--bgE)', border: '1px solid var(--bd)',
    borderRadius: 4, padding: '4px 8px', fontSize: 11, color: 'var(--tx)',
    fontFamily: 'var(--fn)', outline: 'none', minWidth: 0,
  };

  return (
    <div style={{ padding: '12px 14px', overflowY: 'auto', height: '100%' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: 12 }}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--ac)" strokeWidth="2" style={{ flexShrink: 0, marginRight: 8 }}>
          <circle cx="5" cy="19" r="3"/><circle cx="19" cy="5" r="3"/>
          <path d="M5 16V9a4 4 0 014-4h6"/><polyline points="15 1 19 5 15 9"/>
        </svg>
        <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--tx)', fontFamily: 'var(--fd)' }}>
          Path Analysis
        </span>
        <button onClick={onClear} style={{
          marginLeft: 'auto', fontSize: 10, color: 'var(--txD)',
          background: 'none', border: '1px solid var(--bd)', borderRadius: 4,
          padding: '2px 8px', cursor: 'pointer', fontFamily: 'var(--fn)',
        }}>Close</button>
      </div>

      {/* Source / Target inputs */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 10, color: 'var(--txD)', width: 42, flexShrink: 0 }}>Source</span>
          <input
            value={srcInput} onChange={e => setSrcInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="IP address"
            style={inputStyle}
          />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 10, color: 'var(--txD)', width: 42, flexShrink: 0 }}>Target</span>
          <input
            value={tgtInput} onChange={e => setTgtInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="IP address"
            style={inputStyle}
          />
        </div>
      </div>

      {/* Controls row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
        <button
          onClick={() => setDirected(d => !d)}
          style={{
            fontSize: 10, padding: '3px 8px', borderRadius: 4, cursor: 'pointer',
            fontFamily: 'var(--fn)',
            background: directed ? 'rgba(88,166,255,.12)' : 'var(--bgE)',
            color: directed ? 'var(--ac)' : 'var(--txM)',
            border: directed ? '1px solid rgba(88,166,255,.3)' : '1px solid var(--bd)',
          }}
        >
          {directed ? 'Directed' : 'Undirected'}
        </button>
        <button className="btn" onClick={handleRun}
          style={{ fontSize: 10, padding: '3px 10px' }}>
          Find
        </button>
      </div>

      {/* No results */}
      {pathResult && pathCount === 0 && (
        <div style={{ fontSize: 11, color: 'var(--txD)', padding: '20px 0', textAlign: 'center' }}>
          No paths found between these nodes.
        </div>
      )}

      {/* Results */}
      {pathCount > 0 && (
        <>
          {/* Summary */}
          <div style={{
            fontSize: 10, color: 'var(--txD)', marginBottom: 14,
            padding: '6px 10px', background: 'var(--bgE)', borderRadius: 6,
            border: '1px solid var(--bd)',
          }}>
            <span style={{ color: 'var(--txM)' }}>{pathCount}</span> path{pathCount !== 1 ? 's' : ''} found
            {' · '}<span style={{ color: 'var(--txM)' }}>{nodeCount}</span> node{nodeCount !== 1 ? 's' : ''}
            {' · '}<span style={{ color: 'var(--txM)' }}>{pathEdges.length}</span> edge{pathEdges.length !== 1 ? 's' : ''}
            {' · '}<span style={{ color: 'var(--txM)' }}>{maxHop}</span> max hop{maxHop !== 1 ? 's' : ''}
          </div>

          {/* Hop Layers */}
          <div style={{ marginBottom: 6 }}>
            <div style={{
              fontSize: 10, fontWeight: 600, textTransform: 'uppercase',
              letterSpacing: '.1em', color: 'var(--ac)', marginBottom: 8,
              paddingBottom: 6, borderBottom: '2px solid var(--bgH)',
              fontFamily: 'var(--fd)',
            }}>
              Hop Layers
            </div>

            {Object.keys(hopLayers).sort((a, b) => Number(a) - Number(b)).map(hopStr => {
              const hop = Number(hopStr);
              const nodes = hopLayers[hopStr];
              const isSource = hop === 0;
              const isTarget = hop === maxHop;
              const label = isSource ? 'Source' : isTarget ? 'Target' : `Hop ${hop}`;

              return (
                <div key={hopStr} style={{ marginBottom: 10 }}>
                  <div style={{
                    fontSize: 9, fontWeight: 600, textTransform: 'uppercase',
                    letterSpacing: '.08em', color: 'var(--txD)', marginBottom: 4,
                  }}>
                    {label}
                    {!isSource && !isTarget && (
                      <span style={{ color: 'var(--txD)', fontWeight: 400 }}> · {nodes.length} node{nodes.length !== 1 ? 's' : ''}</span>
                    )}
                  </div>

                  {nodes.map(nodeId => {
                    const edges = nodeEdgeMap[nodeId] || [];
                    const isExpanded = expandedNodes.has(nodeId);
                    const hasEdges = edges.length > 0;

                    return (
                      <div key={nodeId} style={{ marginBottom: 2 }}>
                        <div style={{
                          display: 'flex', alignItems: 'center', gap: 6,
                          padding: '3px 8px', borderRadius: 4,
                          background: (isSource || isTarget) ? 'rgba(88,166,255,.06)' : 'transparent',
                        }}>
                          {/* Expand toggle */}
                          {hasEdges ? (
                            <span
                              onClick={(e) => { e.stopPropagation(); toggleNode(nodeId); }}
                              style={{
                                fontSize: 9, color: 'var(--txD)', cursor: 'pointer',
                                display: 'inline-block', width: 10, textAlign: 'center',
                                transform: isExpanded ? 'rotate(90deg)' : 'rotate(0)',
                                transition: 'transform .15s',
                              }}
                            >▶</span>
                          ) : (
                            <span style={{ width: 10 }} />
                          )}

                          {/* Node ID — clickable */}
                          <span
                            onClick={() => onSelectNode?.(nodeId)}
                            style={{
                              fontSize: 11, fontFamily: 'var(--fn)',
                              color: (isSource || isTarget) ? 'var(--ac)' : 'var(--tx)',
                              fontWeight: (isSource || isTarget) ? 600 : 400,
                              cursor: 'pointer',
                            }}
                          >
                            {nodeId}
                          </span>

                          {hasEdges && (
                            <span style={{ fontSize: 9, color: 'var(--txD)', marginLeft: 'auto' }}>
                              {edges.length} edge{edges.length !== 1 ? 's' : ''}
                            </span>
                          )}
                        </div>

                        {/* Expanded edges for this node */}
                        {isExpanded && edges.map((edge, i) => {
                          const otherNode = edge.source === nodeId ? edge.target : edge.source;
                          return (
                            <div
                              key={i}
                              onClick={() => {
                                const graphEdge = findGraphEdge(edge.source, edge.target);
                                if (graphEdge && onSelectEdge) onSelectEdge(graphEdge);
                              }}
                              style={{
                                display: 'flex', alignItems: 'center', gap: 6,
                                padding: '2px 8px 2px 26px', fontSize: 10,
                                cursor: 'pointer', borderRadius: 3,
                              }}
                              className="hovRow"
                            >
                              <span style={{ color: 'var(--txD)' }}>→</span>
                              <span style={{ fontFamily: 'var(--fn)', color: 'var(--txM)' }}>{otherNode}</span>
                              <span style={{ display: 'flex', gap: 3, marginLeft: 'auto' }}>
                                {edge.protocols?.map(p => (
                                  <Tag key={p} color={pColors?.[p] || '#8b949e'} small>{p}</Tag>
                                ))}
                              </span>
                              {edge.total_bytes > 0 && (
                                <span style={{ fontSize: 9, color: 'var(--txD)', fontFamily: 'var(--fn)' }}>
                                  {fB(edge.total_bytes)}
                                </span>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    );
                  })}
                </div>
              );
            })}
          </div>

          {/* All Edges summary */}
          <div>
            <div style={{
              fontSize: 10, fontWeight: 600, textTransform: 'uppercase',
              letterSpacing: '.1em', color: 'var(--ac)', marginBottom: 8,
              paddingBottom: 6, borderBottom: '2px solid var(--bgH)',
              fontFamily: 'var(--fd)',
            }}>
              All Edges ({pathEdges.length})
            </div>

            {pathEdges.map((edge, i) => (
              <div
                key={i}
                onClick={() => {
                  const graphEdge = findGraphEdge(edge.source, edge.target);
                  if (graphEdge && onSelectEdge) onSelectEdge(graphEdge);
                }}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  padding: '4px 8px', fontSize: 10, cursor: 'pointer',
                  borderRadius: 4,
                }}
                className="hovRow"
              >
                <span style={{ fontFamily: 'var(--fn)', color: 'var(--tx)', minWidth: 0 }}>
                  {edge.source}
                </span>
                <span style={{ color: 'var(--txD)', flexShrink: 0 }}>→</span>
                <span style={{ fontFamily: 'var(--fn)', color: 'var(--tx)', minWidth: 0 }}>
                  {edge.target}
                </span>
                <span style={{ display: 'flex', gap: 3, marginLeft: 'auto', flexShrink: 0 }}>
                  {edge.protocols?.map(p => (
                    <Tag key={p} color={pColors?.[p] || '#8b949e'} small>{p}</Tag>
                  ))}
                </span>
                {edge.total_bytes > 0 && (
                  <span style={{ fontSize: 9, color: 'var(--txD)', fontFamily: 'var(--fn)', flexShrink: 0 }}>
                    {fB(edge.total_bytes)}
                  </span>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
