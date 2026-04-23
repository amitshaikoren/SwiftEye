import React from 'react';
import { NODE_LEGENDS, EDGE_LEGENDS } from './graphLegendData';

const NODE_MODE_LABELS = {
  address: 'Nodes: Address type',
  os: 'Nodes: OS guess',
  protocol: 'Nodes: Protocol',
  volume: 'Nodes: Volume',
};
const EDGE_MODE_LABELS = {
  protocol: 'Edges: Protocol',
  volume: 'Edges: Volume',
  sessions: 'Edges: Sessions',
};

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
                <circle cx="5" cy="5" r="4" fill={item.fill} stroke={item.stroke} strokeWidth="1.5" />
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
  const nodeItems = NODE_LEGENDS[nodeColorMode];
  const edgeItems = EDGE_LEGENDS[edgeColorMode];

  if (!nodeItems && !edgeItems) return null;

  return (
    <div style={{
      position: 'absolute', bottom: 12, left: 12, zIndex: 8,
      background: 'rgba(8,9,13,0.88)', border: '1px solid var(--bdL)',
      borderRadius: 6, padding: '8px 10px', minWidth: 160, maxWidth: 200,
      backdropFilter: 'blur(4px)',
    }}>
      {nodeItems && (
        <LegendSection
          title={NODE_MODE_LABELS[nodeColorMode] || 'Nodes'}
          items={nodeItems}
          dot={true}
          hiddenLabels={hiddenLabels}
          onToggle={onToggle}
        />
      )}
      {edgeItems && nodeItems && (
        <div style={{ height: 1, background: 'var(--bgH)', margin: '4px 0 8px' }} />
      )}
      {edgeItems && (
        <LegendSection
          title={EDGE_MODE_LABELS[edgeColorMode] || 'Edges'}
          items={edgeItems}
          dot={false}
          hiddenLabels={hiddenLabels}
          onToggle={onToggle}
        />
      )}
    </div>
  );
}
