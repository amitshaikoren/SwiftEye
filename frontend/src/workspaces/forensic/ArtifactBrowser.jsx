/**
 * Forensic workspace — artifact browser (left panel).
 *
 * Replaces the network protocol list when the forensic workspace is active.
 * Top-level rows are entity types (process / file / registry / endpoint);
 * children are the edge types originating from that entity. Clicking an
 * edge-type child toggles its visibility via hiddenEdgeTypes.
 *
 * Type metadata (color, label) is read from `workspace.schema` exclusively —
 * adding a node/edge type only requires editing `backend/workspaces/forensic/
 * schema.py`. The visual language matches LeftPanel's protocol tree.
 */

import React, { useMemo, useState } from 'react';
import { fN } from '@core/utils';

export default function ArtifactBrowser({ graph, hiddenEdgeTypes, setHiddenEdgeTypes, schema }) {
  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];

  const [collapsed, setCollapsed] = useState({});
  const toggleCollapse = key => setCollapsed(c => ({ ...c, [key]: !c[key] }));

  // Build {nodeType -> meta} and {edgeType -> meta} from schema.
  // Falls back to a neutral grey row if the type isn't declared.
  const nodeMetaByName = useMemo(() => {
    const m = {};
    for (const nt of (schema?.node_types || [])) m[nt.name] = nt;
    return m;
  }, [schema]);
  const edgeMetaByName = useMemo(() => {
    const m = {};
    for (const et of (schema?.edge_types || [])) m[et.name] = et;
    return m;
  }, [schema]);

  // Schema declaration order is the canonical display order.
  const orderedNodeTypes = useMemo(
    () => (schema?.node_types || []).map(nt => nt.name),
    [schema]
  );

  // Per-type node counts.
  const nodeTypeCounts = useMemo(() => {
    const counts = {};
    for (const n of nodes) {
      if (n.type) counts[n.type] = (counts[n.type] || 0) + 1;
    }
    return counts;
  }, [nodes]);

  // node id → type, so we can attribute each edge to its source's node type.
  const nodeTypeMap = useMemo(() => {
    const m = {};
    for (const n of nodes) m[n.id] = n.type;
    return m;
  }, [nodes]);

  // {sourceNodeType: {edgeType: count}}
  const edgeTypeCounts = useMemo(() => {
    const counts = {};
    for (const e of edges) {
      const srcId = e.source?.id || e.source;
      const srcType = nodeTypeMap[srcId];
      if (!srcType) continue;
      const et = e.type || 'unknown';
      if (!counts[srcType]) counts[srcType] = {};
      counts[srcType][et] = (counts[srcType][et] || 0) + 1;
    }
    return counts;
  }, [edges, nodeTypeMap]);

  function toggleEdgeType(edgeType) {
    setHiddenEdgeTypes(prev => {
      const next = new Set(prev);
      if (next.has(edgeType)) next.delete(edgeType);
      else next.add(edgeType);
      return next;
    });
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <div className="sh" style={{ marginBottom: 0 }}>Artifacts</div>
        {hiddenEdgeTypes.size > 0 && (
          <button
            className="btn"
            style={{ padding: '1px 6px', fontSize: 10 }}
            onClick={() => setHiddenEdgeTypes(new Set())}
          >All</button>
        )}
      </div>

      {orderedNodeTypes.map(nodeType => {
        const count = nodeTypeCounts[nodeType];
        if (!count) return null;
        const meta = nodeMetaByName[nodeType] || { color: '#8b949e', label: nodeType };
        const actionCounts = edgeTypeCounts[nodeType] || {};
        const childKeys = Object.keys(actionCounts);
        const hasChildren = childKeys.length > 0;
        const isCollapsed = collapsed[nodeType];

        return (
          <div key={nodeType} style={{ marginBottom: 2 }}>
            {/* Entity-type row — same shape as the IPv4/IPv6 group header
                in LeftPanel's protocol tree (toggle arrow + label + count). */}
            <div
              onClick={() => hasChildren && toggleCollapse(nodeType)}
              style={{
                display: 'flex', alignItems: 'center', gap: 4,
                padding: '3px 0', cursor: hasChildren ? 'pointer' : 'default',
              }}
            >
              {hasChildren ? (
                <span style={{ fontSize: 9, color: 'var(--txD)', width: 10, textAlign: 'center', flexShrink: 0, userSelect: 'none' }}>
                  {isCollapsed ? '▸' : '▾'}
                </span>
              ) : (
                <span style={{ width: 10, flexShrink: 0 }} />
              )}
              <span style={{
                width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                background: meta.color,
              }} />
              <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--txM)', flex: 1 }}>
                {meta.label}
              </span>
              <span style={{ fontSize: 9, color: 'var(--txD)', fontFamily: 'var(--fn)' }}>
                {fN(count)}
              </span>
            </div>

            {/* Edge-type rows — same shape as transport rows under IPv4/IPv6
                in LeftPanel: indented 10px, square colour swatch with border,
                opacity-fade on hidden state. */}
            {!isCollapsed && hasChildren && childKeys.map(edgeType => {
              const em = edgeMetaByName[edgeType] || { color: '#8b949e', label: edgeType };
              const cnt = actionCounts[edgeType];
              const isHidden = hiddenEdgeTypes.has(edgeType);

              return (
                <div key={edgeType} style={{ marginLeft: 10 }}>
                  <div
                    onClick={() => toggleEdgeType(edgeType)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 5,
                      padding: '2px 0', cursor: 'pointer',
                      opacity: isHidden ? 0.3 : 1,
                      transition: 'opacity .15s',
                    }}
                  >
                    <span style={{ width: 10, flexShrink: 0 }} />
                    <span style={{
                      width: 8, height: 8, borderRadius: 2, flexShrink: 0,
                      background: isHidden ? 'transparent' : em.color,
                      border: '1.5px solid ' + em.color,
                    }} />
                    <span style={{ fontSize: 10, fontWeight: 500, color: 'var(--txM)', flex: 1 }}>
                      {em.label}
                    </span>
                    <span style={{ fontSize: 9, color: 'var(--txD)', fontFamily: 'var(--fn)' }}>
                      {fN(cnt)}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        );
      })}

      {nodes.length === 0 && (
        <div style={{ fontSize: 10, color: 'var(--txD)', marginTop: 4 }}>No artifacts loaded.</div>
      )}
    </div>
  );
}
