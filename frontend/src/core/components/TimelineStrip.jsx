/**
 * TimelineStrip — gap-split sparkline design.
 *
 * The backend already collapses large empty gaps into a single is_gap marker
 * bucket. This component renders:
 *   - Each non-gap segment as a bar chart, sized proportionally by packet count
 *   - Each gap marker as a narrow //// hatch region
 *
 * No bucket size selector. No viewport. No activeBurst state.
 * Sliders always span the full timeline (global indices).
 * Clicking a segment label snaps the sliders to that segment.
 *
 * The gap-split view means both bursts are always visible and fill real
 * screen space regardless of how far apart they are in time.
 */
import React, { useMemo } from 'react';

const GAP_W   = 56;  // px — fixed width for each gap marker
const BAR_CLR = '#378ADD';
const BAR_DIM = 'rgba(128,128,128,0.15)';
const SEL_CLR = 'rgba(55,138,221,0.08)';

function fmtTs(t) {
  if (!t) return '—';
  const d = new Date(t * 1000);
  const dd   = String(d.getDate()).padStart(2, '0');
  const mm   = String(d.getMonth() + 1).padStart(2, '0');
  const yyyy = d.getFullYear();
  const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  return `${dd}/${mm}/${yyyy} ${time}`;
}

function fmtDuration(sec) {
  if (sec < 60)   return `${Math.round(sec)}s`;
  if (sec < 3600) return `${Math.round(sec / 60)}m`;
  if (sec < 86400) return `${(sec / 3600).toFixed(1)}h`;
  return `${(sec / 86400).toFixed(1)}d`;
}

// Split timeline into alternating segments and gap markers
function splitTimeline(timeline) {
  const parts = []; // [{type:'segment'|'gap', buckets, gapSec, globalStart, globalEnd}]
  let i = 0;
  while (i < timeline.length) {
    if (timeline[i]?.is_gap) {
      parts.push({
        type: 'gap',
        gapSec: timeline[i].gap_seconds || 0,
        globalStart: i,
        globalEnd: i,
      });
      i++;
    } else {
      const segStart = i;
      while (i < timeline.length && !timeline[i]?.is_gap) i++;
      parts.push({
        type: 'segment',
        buckets: timeline.slice(segStart, i),
        globalStart: segStart,
        globalEnd: i - 1,
      });
    }
  }
  return parts;
}

// Draw one segment's bars onto a canvas
function drawSegment(canvas, buckets, activeRange, globalStart, width, height) {
  if (!canvas || !buckets.length || width < 1) return;
  const dpr = window.devicePixelRatio || 1;
  canvas.width  = Math.round(width * dpr);
  canvas.height = Math.round(height * dpr);
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, width, height);

  const max = Math.max(...buckets.map(b => b.packet_count || 0), 1);
  const bw  = width / buckets.length;
  const [rS, rE] = activeRange;

  // Selection background
  const selStart = Math.max(rS, globalStart);
  const selEnd   = Math.min(rE, globalStart + buckets.length - 1);
  if (selEnd >= selStart) {
    const sx = ((selStart - globalStart) / buckets.length) * width;
    const sw = ((selEnd - selStart + 1) / buckets.length) * width;
    ctx.fillStyle = SEL_CLR;
    ctx.fillRect(sx, 0, sw, height);
  }

  // Bars
  buckets.forEach((b, i) => {
    const v = b.packet_count || 0;
    const gi = globalStart + i;
    const x = i * bw;
    const h = (v / max) * (height - 3);
    ctx.fillStyle = (gi >= rS && gi <= rE) ? BAR_CLR : BAR_DIM;
    ctx.fillRect(x, height - 1 - h, Math.max(bw - 0.4, 0.8), Math.max(h, v > 0 ? 2 : 0));
  });

  // Start/end handle lines
  if (rS >= globalStart && rS <= globalStart + buckets.length - 1) {
    const hx = ((rS - globalStart) / buckets.length) * width;
    ctx.strokeStyle = BAR_CLR; ctx.lineWidth = 1.5; ctx.setLineDash([]);
    ctx.beginPath(); ctx.moveTo(hx, 0); ctx.lineTo(hx, height); ctx.stroke();
    ctx.fillStyle = BAR_CLR; ctx.fillRect(hx - 2, 0, 4, 4);
  }
  if (rE >= globalStart && rE <= globalStart + buckets.length - 1) {
    const hx = ((rE - globalStart + 1) / buckets.length) * width;
    ctx.strokeStyle = '#1D9E75'; ctx.lineWidth = 1.5;
    ctx.beginPath(); ctx.moveTo(hx, 0); ctx.lineTo(hx, height); ctx.stroke();
    ctx.fillStyle = '#1D9E75'; ctx.fillRect(hx - 2, 0, 4, 4);
  }
}

// Individual segment canvas component
function SegmentCanvas({ buckets, activeRange, globalStart, width, height }) {
  const ref = React.useRef(null);
  React.useEffect(() => {
    drawSegment(ref.current, buckets, activeRange, globalStart, width, height);
  }, [buckets, activeRange, globalStart, width, height]);
  return <canvas ref={ref} style={{ width, height, display: 'block' }} />;
}

// Compute the pixel x-position of a timestamp within the gap-split layout.
// Returns null if the time is outside the capture range.
function cursorX(time, timeline, parts, perSegW, totalWidth) {
  if (!time || !timeline.length) return null;
  let pixelOffset = 0;
  for (const part of parts) {
    if (part.type === 'gap') {
      pixelOffset += GAP_W;
      continue;
    }
    const { buckets, globalStart } = part;
    const segW = perSegW;
    // Check if time falls within this segment
    const firstBucket = buckets[0];
    const lastBucket  = buckets[buckets.length - 1];
    if (!firstBucket || !lastBucket) { pixelOffset += segW; continue; }
    const segStart = firstBucket.start_time;
    const segEnd   = lastBucket.end_time || lastBucket.start_time;
    if (time >= segStart && time <= segEnd) {
      const frac = (segEnd > segStart) ? (time - segStart) / (segEnd - segStart) : 0;
      return pixelOffset + frac * segW;
    }
    pixelOffset += segW;
  }
  return null;
}

export default function TimelineStrip({
  timeline, timeRange, setTimeRange,
  bucketSec, setBucketSec, width,
  animCursorTime,
}) {
  const N = timeline.length;
  const parts = useMemo(() => splitTimeline(timeline), [timeline]);

  // How many segments are there (non-gap parts)?
  const segments = parts.filter(p => p.type === 'segment');
  const hasGaps  = parts.some(p => p.type === 'gap');

  // Allocate widths: gaps get GAP_W px each, segments share the rest EQUALLY
  const totalGapW  = parts.filter(p => p.type === 'gap').length * GAP_W;
  const segW       = Math.max(1, width - totalGapW);
  const segCount   = segments.length || 1;
  const perSegW    = Math.floor(segW / segCount);

  const startTs = fmtTs(timeline[timeRange[0]]?.start_time);
  const endTs   = fmtTs(timeline[timeRange[1]]?.end_time);

  return (
    <div style={{ background: 'var(--bgP)', borderTop: '1px solid var(--bd)', padding: '5px 16px 6px', flexShrink: 0 }}>

      {/* Row 1: segment snap buttons + timestamps */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 3 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 9, color: 'var(--txM)', textTransform: 'uppercase', letterSpacing: '.06em' }}>Timeline</span>
          {setTimeRange && [1, 5, 15, 30, 60].map(s => (
            <button key={s} className={'btn' + (bucketSec === s ? ' on' : '')}
              onClick={() => setBucketSec(s)} style={{ padding: '1px 5px', fontSize: 9 }}>{s}s</button>
          ))}
          {setTimeRange && hasGaps && (
            <>
              {segments.map((seg, i) => (
                <button key={i}
                  className={'btn' + (timeRange[0] === seg.globalStart && timeRange[1] === seg.globalEnd ? ' on' : '')}
                  style={{ fontSize: 9, padding: '1px 7px' }}
                  onClick={() => setTimeRange([seg.globalStart, seg.globalEnd])}>
                  Burst {i + 1}
                </button>
              ))}
              <button
                className={'btn' + (timeRange[0] === 0 && timeRange[1] === N - 1 ? ' on' : '')}
                style={{ fontSize: 9, padding: '1px 7px' }}
                onClick={() => setTimeRange([0, N - 1])}>
                All
              </button>
            </>
          )}
        </div>
        {/* Timestamps */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 9, fontFamily: 'var(--fn)', flexShrink: 0, marginLeft: 8 }}>
          <span style={{ color: '#378ADD' }}>{startTs}</span>
          <span style={{ color: 'var(--txD)' }}>→</span>
          <span style={{ color: '#1D9E75' }}>{endTs}</span>
        </div>
      </div>

      {/* Row 2: gap-split sparkline */}
      <div style={{ display: 'flex', alignItems: 'stretch', gap: 0, height: 30, position: 'relative' }}>
        {/* Animation frame cursor */}
        {animCursorTime != null && (() => {
          const cx = cursorX(animCursorTime, timeline, parts, perSegW, width);
          if (cx == null) return null;
          return (
            <div style={{
              position: 'absolute', top: 0, bottom: 0, width: 1.5,
              background: '#f0a040', opacity: 0.85, pointerEvents: 'none', zIndex: 2,
              left: cx,
            }}>
              <div style={{
                position: 'absolute', top: 0, left: -3, width: 7, height: 7,
                background: '#f0a040', clipPath: 'polygon(50% 100%, 0 0, 100% 0)',
              }} />
            </div>
          );
        })()}
        {parts.map((part, pi) => {
          if (part.type === 'gap') {
            // Gap marker: //// hatch with duration label
            return (
              <div key={pi} style={{
                width: GAP_W, flexShrink: 0, height: 30, position: 'relative',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                overflow: 'hidden',
              }}>
                {/* Hatch lines */}
                <svg width={GAP_W} height={30} style={{ position: 'absolute', top: 0, left: 0 }}>
                  {[-10, -2, 6, 14, 22, 30, 38].map((x, i) => (
                    <line key={i} x1={x} y1={30} x2={x + 24} y2={0}
                      stroke="rgba(160,160,160,0.5)" strokeWidth="2" />
                  ))}
                </svg>
                {/* Duration */}
                <span style={{
                  position: 'relative', fontSize: 9, color: 'var(--txD)',
                  background: 'var(--bgP)', padding: '0 2px', zIndex: 1,
                }}>
                  {fmtDuration(part.gapSec)}
                </span>
              </div>
            );
          }
          // Normal segment
          const w = perSegW;
          return (
            <SegmentCanvas key={pi}
              buckets={part.buckets}
              activeRange={timeRange}
              globalStart={part.globalStart}
              width={Math.max(1, w)}
              height={30}
            />
          );
        })}
      </div>

      {/* Rows 3+4: Start/End sliders — only shown when the workspace supports time-range filtering */}
      {setTimeRange && (
        <>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 4 }}>
            <span style={{ fontSize: 9, color: 'var(--txD)', width: 30, flexShrink: 0 }}>Start</span>
            <input type="range" min={0} max={N - 1} value={timeRange[0]}
              onChange={e => { const v = +e.target.value; setTimeRange([v, Math.max(v, timeRange[1])]); }}
              style={{ flex: 1 }} />
            <span style={{ fontSize: 9, color: '#378ADD', minWidth: 155, textAlign: 'right', fontFamily: 'var(--fn)' }}>{startTs}</span>
          </div>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 2 }}>
            <span style={{ fontSize: 9, color: 'var(--txD)', width: 30, flexShrink: 0 }}>End</span>
            <input type="range" min={0} max={N - 1} value={timeRange[1]}
              onChange={e => { const v = +e.target.value; setTimeRange([Math.min(timeRange[0], v), v]); }}
              style={{ flex: 1 }} />
            <span style={{ fontSize: 9, color: '#1D9E75', minWidth: 155, textAlign: 'right', fontFamily: 'var(--fn)' }}>{endTs}</span>
          </div>
        </>
      )}

    </div>
  );
}
