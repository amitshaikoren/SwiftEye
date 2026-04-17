import React from 'react';

export default function Row({ l, v }) {
  return (
    <div className="rw">
      <span className="rl">{l}</span>
      <span className="rv">{v}</span>
    </div>
  );
}
