import React from 'react';
import { NODE_LEGENDS, EDGE_LEGENDS } from './graphLegendData';
import { useWorkspace } from '@/WorkspaceProvider';

// Phase 5.7 — mode-id → header-label map. Workspace-declared modes contribute
// labels via the descriptor; this map covers network's pre-5.7 mode ids and
// stays as a fallback when a mode lacks a `label` in the descriptor.
const _FALLBACK_NODE_LABELS = {
  address: 'Address type',
  os: 'OS guess',
  protocol: 'Protocol',
  volume: 'Volume',
};
const _FALLBACK_EDGE_LABELS = {
  protocol: 'Protocol',
  volume: 'Volume',
  sessions: 'Sessions',
};

function _resolveLegend(modes, modeId, staticMap, workspace) {
  const m = (modes || []).find(x => x.id === modeId);
  if (m?.legendItems) {
    return typeof m.legendItems === 'function' ? m.legendItems(workspace) : m.legendItems;
  }
  return staticMap[modeId];
}
function _resolveLabel(modes, modeId, fallbackMap) {
  const m = (modes || []).find(x => x.id === modeId);
  return m?.label || fallbackMap[modeId];
}

function LegendSection({ title, items, dot, hiddenLabels, onToggle }) {
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ fontSize: 9, color: 'var(--txD)', fontFamily: 'var(--fn)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
        {title}
      </div>
      {items.map((item, i) => {
        const hidden = hiddenLabels?.has(item.label);
        const filterable = !!item.filter;
        return (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3, opacity: hidden ? 0.4 : 1 }}>
            {dot ? (
              <svg width="10" height="10" style={{ flexShrink: 0 }}>
                <circle cx="5" cy="5" r="4" fill={item.fill} stroke={item.stroke || item.fill} strokeWidth="1.5" />
              </svg>
            ) : (
              <svg width="14" height="4" style={{ flexShrink: 0 }}>
                <line x1="0" y1="2" x2="14" y2="2" stroke={item.fill} strokeWidth="3" />
              </svg>
            )}
            <span style={{ flex: 1, fontSize: 10, color: 'var(--txM)', fontFamily: 'var(--fn)' }}>{item.label}</span>
            {filterable && (
              <button
                onClick={() => onToggle?.(item)}
                title={hidden ? 'Show (remove hide step)' : 'Hide (add to recipe)'}
                style={{
                  background: 'none', border: 'none', cursor: 'pointer', padding: '0 2px',
                  color: hidden ? 'var(--txD)' : 'var(--txM)', fontSize: 10, lineHeight: 1, flexShrink: 0,
                }}
              >
                {hidden ? '🚫' : '👁'}
              </button>
            )}
          </div>
        );
      })}
    </div>
  );
}

export default function GraphLegend({ nodeColorMode, edgeColorMode, hiddenLabels, onToggle }) {
  const workspace = useWorkspace();
  // Phase 5.7 escape hatch: a workspace can opt out of the graph display
  // catalog entirely with `graphDisplay: null`. In that case there is no
  // mode-driven legend to show.
  if (workspace.graphDisplay === null) return null;
  const gd = workspace.graphDisplay || {};
  const nodeItems = _resolveLegend(gd.nodeColorModes, nodeColorMode, NODE_LEGENDS, workspace);
  // Network: protocol bar already shows edge protocols; suppress the duplicate edge legend.
  // Forensic / other workspaces don't use 'protocol' mode for edges, so this is a no-op there.
  const rawEdgeItems = _resolveLegend(gd.edgeColorModes, edgeColorMode, EDGE_LEGENDS, workspace);
  const edgeItems = edgeColorMode === 'protocol' ? null : rawEdgeItems;

  if (!nodeItems?.length && !edgeItems?.length) return null;

  const nodeTitle = 'Nodes: ' + (_resolveLabel(gd.nodeColorModes, nodeColorMode, _FALLBACK_NODE_LABELS) || nodeColorMode);
  const edgeTitle = 'Edges: ' + (_resolveLabel(gd.edgeColorModes, edgeColorMode, _FALLBACK_EDGE_LABELS) || edgeColorMode);

  return (
    <div style={{
      background: 'rgba(8,9,13,0.88)', border: '1px solid var(--bdL)',
      borderRadius: 6, padding: '8px 10px', minWidth: 160, maxWidth: 200,
      backdropFilter: 'blur(4px)',
    }}>
      {nodeItems?.length ? (
        <LegendSection title={nodeTitle} items={nodeItems} dot={true} hiddenLabels={hiddenLabels} onToggle={onToggle} />
      ) : null}
      {edgeItems?.length && nodeItems?.length ? (
        <div style={{ height: 1, background: 'var(--bgH)', margin: '4px 0 8px' }} />
      ) : null}
      {edgeItems?.length ? (
        <LegendSection title={edgeTitle} items={edgeItems} dot={false} hiddenLabels={hiddenLabels} onToggle={onToggle} />
      ) : null}
    </div>
  );
}
