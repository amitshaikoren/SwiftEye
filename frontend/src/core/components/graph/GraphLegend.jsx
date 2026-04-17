import React from 'react';
import { NODE_LEGENDS, EDGE_LEGENDS } from './graphLegendData';

// Mode labels shown in the legend header
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

function LegendSection({ title, items, dot }) {
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ fontSize: 9, color: 'var(--txD)', fontFamily: 'var(--fn)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
        {title}
      </div>
      {items.map((item, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
          {dot ? (
            <svg width="10" height="10" style={{ flexShrink: 0 }}>
              <circle cx="5" cy="5" r="4" fill={item.fill} stroke={item.stroke} strokeWidth="1.5" />
            </svg>
          ) : (
            <svg width="14" height="4" style={{ flexShrink: 0 }}>
              <line x1="0" y1="2" x2="14" y2="2" stroke={item.fill} strokeWidth="3" />
            </svg>
          )}
          <span style={{ fontSize: 10, color: 'var(--txM)', fontFamily: 'var(--fn)' }}>{item.label}</span>
        </div>
      ))}
    </div>
  );
}

export default function GraphLegend({ nodeColorMode, edgeColorMode }) {
  const nodeItems = NODE_LEGENDS[nodeColorMode];
  const edgeItems = EDGE_LEGENDS[edgeColorMode];

  // Don't render legend for custom rules — no static mapping to show
  if (!nodeItems && !edgeItems) return null;

  return (
    <div style={{
      position: 'absolute', bottom: 12, left: 12, zIndex: 8,
      background: 'rgba(8,9,13,0.88)', border: '1px solid var(--bdL)',
      borderRadius: 6, padding: '8px 10px', minWidth: 150, maxWidth: 190,
      backdropFilter: 'blur(4px)',
    }}>
      {nodeItems && (
        <LegendSection
          title={NODE_MODE_LABELS[nodeColorMode] || 'Nodes'}
          items={nodeItems}
          dot={true}
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
        />
      )}
    </div>
  );
}
