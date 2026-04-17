import React, { useState, useEffect, useContext, createContext } from 'react';

// Context for per-panel collapse state persistence
// Value: { state: Map<string, boolean>, toggle: (title) => void }
// Map stores explicitly toggled titles → open/closed.
// Titles NOT in the map fall back to the component's `open` prop default.
export const CollapseContext = createContext(null);

export default function Collapse({ title, children, open: defaultOpen = false, level, card = true }) {
  const ctx = useContext(CollapseContext);
  // If context has an explicit entry for this title, use it; otherwise use defaultOpen
  const externalOpen = ctx ? (ctx.state.has(title) ? ctx.state.get(title) : defaultOpen) : undefined;
  const [localOpen, setLocalOpen] = useState(defaultOpen);
  useEffect(() => { setLocalOpen(defaultOpen); }, [defaultOpen]);

  const isOpen = externalOpen !== undefined ? externalOpen : localOpen;
  const handleToggle = () => {
    if (ctx) { ctx.toggle(title, !isOpen); }
    else { setLocalOpen(!localOpen); }
  };

  const isLayer = level === 'layer';

  return (
    <div style={{ marginBottom: isLayer ? 10 : 8 }}>
      <div
        className="ch"
        onClick={handleToggle}
        style={{
          fontSize: isLayer ? 11 : 10,
          fontWeight: 600,
          textTransform: 'uppercase',
          letterSpacing: isLayer ? '.1em' : '.1em',
          color: isLayer ? 'var(--ac)' : 'var(--txM)',
          marginBottom: isOpen ? 6 : 0,
          padding: isLayer ? undefined : '8px 0 6px',
          cursor: 'pointer',
          ...(isLayer ? { marginTop: 20, paddingBottom: 6, borderBottom: '2px solid var(--bgH)', fontFamily: 'var(--fd)' } : {}),
        }}
      >
        <span
          style={{
            display: 'inline-block',
            transform: isOpen ? 'rotate(90deg)' : 'rotate(0)',
            transition: 'transform .15s',
            fontSize: 9,
            color: 'var(--txD)',
          }}
        >
          ▶
        </span>{' '}
        {title}
      </div>
      {isOpen && (
        <div className={'fi' + (card && !isLayer ? ' cb' : '')}>
          {children}
        </div>
      )}
    </div>
  );
}
