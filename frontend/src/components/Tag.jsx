import React from 'react';

export default function Tag({ children, color, small, tip }) {
  return (
    <span
      className={'tag' + (small ? ' tag-s' : '')}
      style={{
        background: color + '18',
        color,
        border: '1px solid ' + color + '33',
        cursor: tip ? 'help' : 'default',
      }}
      title={tip || ''}
    >
      {children}
    </span>
  );
}
