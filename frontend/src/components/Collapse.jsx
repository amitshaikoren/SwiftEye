import React, { useState } from 'react';

export default function Collapse({ title, children, open: defaultOpen = false }) {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <div style={{ marginBottom: 8 }}>
      <div
        className="ch"
        onClick={() => setIsOpen(!isOpen)}
        style={{
          fontSize: 10,
          fontWeight: 600,
          textTransform: 'uppercase',
          letterSpacing: '.1em',
          color: 'var(--txM)',
          marginBottom: isOpen ? 6 : 0,
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
