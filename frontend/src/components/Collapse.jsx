import React, { useState, useEffect, useContext, createContext } from 'react';

// Context for per-panel collapse state persistence
// Value: { state: Map<string, boolean>, toggle: (title) => void }
// Map stores explicitly toggled titles → open/closed.
// Titles NOT in the map fall back to the component's `open` prop default.
export const CollapseContext = createContext(null);

export default function Collapse({ title, children, open: defaultOpen = false, level }) {
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
          letterSpacing: isLayer ? '.08em' : '.1em',
          color: isLayer ? 'var(--tx)' : 'var(--txM)',
          marginBottom: isOpen ? 6 : 0,
          cursor: 'pointer',
          ...(isLayer ? { marginTop: 14, paddingBottom: 4, borderBottom: '1px solid var(--bd)' } : {}),
        }}
      >
        <span
          style={{
            display: 'inline-block',
            transform: isOpen ? 'rotate(90deg)' : 'rotate(0)',
            transition: 'transform .15s',
            fontSize: 8,
          }}
        >
          ▶
        </span>{' '}
        {title}
      </div>
      {isOpen && <div className="fi">{children}</div>}
    </div>
  );
}
