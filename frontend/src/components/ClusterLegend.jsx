/**
 * ClusterLegend — overlay showing cluster color/label mapping.
 * Only renders when clustering is active and clusters exist.
 * Click a cluster entry to select it on the graph.
 */

import React, { useState } from 'react';
import { CLUSTER_COLORS } from '../clusterView';

function HexSwatch({ color, size = 12 }) {
  const r = size / 2;
  const points = Array.from({ length: 6 }, (_, i) => {
    const angle = (Math.PI / 3) * i - Math.PI / 6;
    return `${r + r * Math.cos(angle)},${r + r * Math.sin(angle)}`;
  }).join(' ');
  return (
    <svg width={size} height={size} style={{ flexShrink: 0 }}>
      <polygon points={points} fill={color + '30'} stroke={color} strokeWidth={1.5} />
    </svg>
  );
}

export default function ClusterLegend({ nodes, onSelect, clusterNames }) {
  const [collapsed, setCollapsed] = useState(false);

  const clusters = (nodes || [])
    .filter(n => n.is_cluster)
    .sort((a, b) => (b.member_count || 0) - (a.member_count || 0));

  if (clusters.length === 0) return null;

  return (
    <div style={{
      background: 'var(--bgP)', border: '1px solid var(--bd)',
      borderRadius: 'var(--r)', padding: collapsed ? '4px 8px' : '6px 10px',
      opacity: 0.92, maxWidth: 260, maxHeight: 200, overflow: 'hidden',
      display: 'flex', flexDirection: 'column', gap: 2,
    }}>
      {/* Header */}
      <div
        onClick={() => setCollapsed(!collapsed)}
        style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          cursor: 'pointer', userSelect: 'none',
        }}
      >
        <span style={{ fontSize: 9, fontWeight: 600, color: 'var(--txM)', letterSpacing: 0.5, textTransform: 'uppercase' }}>
          Clusters ({clusters.length})
        </span>
        <span style={{ fontSize: 9, color: 'var(--txD)', marginLeft: 8 }}>
          {collapsed ? '\u25B6' : '\u25BC'}
        </span>
      </div>

      {/* Cluster entries */}
      {!collapsed && (
        <div style={{ overflowY: 'auto', maxHeight: 160, display: 'flex', flexDirection: 'column', gap: 1 }}>
          {clusters.map(c => {
            const color = CLUSTER_COLORS[(c.cluster_id || 0) % CLUSTER_COLORS.length];
            const name = clusterNames?.[c.cluster_id] || `Cluster ${c.cluster_id}`;

            return (
              <div
                key={c.id}
                onClick={() => onSelect?.('node', c.id, false)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 5,
                  padding: '2px 4px', borderRadius: 3,
                  cursor: 'pointer', fontSize: 10,
                }}
                onMouseEnter={e => e.currentTarget.style.background = 'var(--bgH)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              >
                <HexSwatch color={color} size={14} />
                <span style={{ color: 'var(--tx)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {name}
                </span>
                <span style={{ color: 'var(--txD)', fontSize: 9, flexShrink: 0 }}>
                  {c.member_count}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
