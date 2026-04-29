import React, { useRef, useEffect } from 'react';

export default function Sparkline({ data, width, height, activeRange }) {
  const ref = useRef(null);

  useEffect(() => {
    const c = ref.current;
    if (!c || !data.length || !width || width < 2) return;
    const dpr = window.devicePixelRatio || 1;
    c.width  = Math.round(width * dpr);
    c.height = Math.round(height * dpr);
    const ctx = c.getContext('2d');
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, width, height);

    const max = Math.max(...data.map(d => d?.packet_count ?? d ?? 0), 1);
    const bw  = width / data.length;
    const [rS, rE] = activeRange || [0, data.length - 1];

    data.forEach((d, i) => {
      const v       = d?.packet_count ?? d ?? 0;
      const isGap   = d?.is_gap === true;
      const x       = i * bw;
      const inRange = i >= rS && i <= rE;

      if (isGap) {
        // Draw //// hatch pattern to indicate skipped time
        const gapW = Math.max(bw, 16);
        ctx.save();
        ctx.strokeStyle = inRange ? 'rgba(55,138,221,0.5)' : 'rgba(128,128,128,0.25)';
        ctx.lineWidth = 1;
        const spacing = 6;
        for (let lx = x - height; lx < x + gapW + height; lx += spacing) {
          ctx.beginPath();
          ctx.moveTo(lx, height);
          ctx.lineTo(lx + height, 0);
          ctx.stroke();
        }
        // Left and right edge lines
        ctx.strokeStyle = inRange ? 'rgba(55,138,221,0.4)' : 'rgba(128,128,128,0.2)';
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke();
        ctx.beginPath(); ctx.moveTo(x + gapW - 0.5, 0); ctx.lineTo(x + gapW - 0.5, height); ctx.stroke();
        ctx.restore();
      } else {
        const h = (v / max) * (height - 4);
        ctx.fillStyle = inRange ? '#378ADD' : 'rgba(128,128,128,0.15)';
        ctx.fillRect(x, height - 2 - h, Math.max(bw - 0.5, 0.8), Math.max(h, v > 0 ? 2 : 0));
      }
    });
  }, [data, width, height, activeRange]);

  return <canvas ref={ref} style={{ width, height, display: 'block' }} />;
}
