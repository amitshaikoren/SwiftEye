import React from 'react';

/**
 * SCOPED / ALL pill toggle.
 * - SCOPED: panel respects the global display filter (protocol + search + IPv6)
 * - ALL:    panel shows unfiltered data
 *
 * Props:
 *   value    'scoped' | 'all'
 *   onChange (value: 'scoped' | 'all') => void
 */
export default function ScopePill({ value, onChange }) {
  const base = {
    padding: '3px 8px',
    cursor: 'pointer',
    letterSpacing: '.04em',
    fontSize: 9,
    userSelect: 'none',
  };
  const active = { color: 'var(--ac)', background: 'rgba(88,166,255,.15)' };
  const inactive = { color: 'var(--txD)', background: 'transparent' };

  return (
    <div style={{
      display: 'flex',
      border: '1px solid var(--bd)',
      borderRadius: 4,
      overflow: 'hidden',
      flexShrink: 0,
    }}>
      <div
        onClick={() => onChange('scoped')}
        style={{ ...base, ...(value === 'scoped' ? active : inactive), borderRight: '1px solid var(--bd)' }}
      >
        SCOPED
      </div>
      <div
        onClick={() => onChange('all')}
        style={{ ...base, ...(value === 'all' ? active : inactive) }}
      >
        ALL
      </div>
    </div>
  );
}
