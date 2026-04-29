import React, { useState } from 'react';
import PlacedCard, { DEFAULT_CARD_HEIGHT, ExpandedOverlay } from './PlacedCard';

// ── Category metadata ─────────────────────────────────────────────────────────
export const CAT_LABELS  = { host: 'Host', session: 'Session', capture: 'Capture', alerts: 'Alerts', other: 'Other' };
export const CAT_COLORS  = { host: 'var(--acG)', session: 'var(--acP)', capture: 'var(--ac)', alerts: 'var(--acR)', other: 'var(--fg3)' };
export const CAT_ORDER   = ['host', 'session', 'capture', 'alerts', 'other'];
const KNOWN_CATS  = new Set(CAT_ORDER);

// Use the category declared by the backend. Falls back to a heuristic for
// custom charts (which are client-side objects with no backend category field),
// and to "other" for any unrecognised value a future chart might declare.
export function inferCategory(chart) {
  if (chart._isCustom) return 'capture';
  const cat = chart.category;
  if (cat && KNOWN_CATS.has(cat)) return cat;
  return 'other';
}

// ── EmptySlot ─────────────────────────────────────────────────────────────────
function EmptySlot({ onDrop, onClick, dragOverId, slotId }) {
  const isOver = dragOverId === slotId;
  return (
    <div
      onClick={onClick}
      onDragOver={e => { e.preventDefault(); onDrop('over', slotId); }}
      onDragLeave={() => onDrop('leave', slotId)}
      onDrop={e => { e.preventDefault(); onDrop('drop', slotId); }}
      style={{
        height: DEFAULT_CARD_HEIGHT, borderRadius: 8,
        border: `1px dashed ${isOver ? 'var(--ac)' : 'var(--bd)'}`,
        background: isOver ? 'rgba(88,166,255,.04)' : '#0a0b0f',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        cursor: 'pointer', transition: 'border-color .15s, background .15s',
      }}
    >
      <div style={{ textAlign: 'center', pointerEvents: 'none', userSelect: 'none' }}>
        <div style={{ fontSize: 20, color: 'var(--bd)', marginBottom: 4 }}>+</div>
        <div style={{ fontSize: 10, color: 'var(--bdL)' }}>Drag a chart here<br/>or click to pick</div>
      </div>
    </div>
  );
}

// ── ChartPicker modal ─────────────────────────────────────────────────────────
export function ChartPicker({ charts, onPick, onClose, onCustom }) {
  const categories = ['host', 'session', 'capture', 'alerts'];
  const grouped = {};
  categories.forEach(c => { grouped[c] = []; });
  charts.forEach(ch => { (grouped[ch._category] || grouped['capture']).push(ch); });

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 300,
      background: 'rgba(0,0,0,.6)', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div style={{
        background: 'var(--bgP)', border: '1px solid var(--bdL)', borderRadius: 10,
        width: 420, maxHeight: '70vh', overflow: 'hidden', display: 'flex', flexDirection: 'column',
        boxShadow: '0 8px 40px rgba(0,0,0,.7)',
      }} onClick={e => e.stopPropagation()}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--bd)', display: 'flex', alignItems: 'center' }}>
          <span style={{ flex: 1, fontSize: 13, fontWeight: 600, color: 'var(--tx)' }}>Pick a chart</span>
          <button className="btn" onClick={onClose} style={{ fontSize: 10, padding: '2px 8px' }}>✕</button>
        </div>
        <div style={{ overflowY: 'auto', padding: '10px 12px' }}>
          {/* Custom chart option at top */}
          {onCustom && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: '.08em', color: 'var(--acP)', marginBottom: 6 }}>Custom</div>
              <div onClick={onCustom}
                style={{ padding: '8px 10px', borderRadius: 6, border: '1px dashed var(--acP)', background: 'rgba(163,113,247,.05)',
                  marginBottom: 6, cursor: 'pointer' }}
                onMouseEnter={e => e.currentTarget.style.background = 'rgba(163,113,247,.12)'}
                onMouseLeave={e => e.currentTarget.style.background = 'rgba(163,113,247,.05)'}>
                <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--acP)' }}>✦ Build custom chart</div>
                <div style={{ fontSize: 10, color: 'var(--txD)', marginTop: 2 }}>Pick a data source and map fields to axes</div>
              </div>
            </div>
          )}
          {categories.map(cat => {
            const items = grouped[cat];
            if (!items?.length) return null;
            return (
              <div key={cat} style={{ marginBottom: 14 }}>
                <div style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: '.08em', color: CAT_COLORS[cat], marginBottom: 6 }}>
                  {CAT_LABELS[cat]}
                </div>
                {items.map(ch => (
                  <div key={ch.name} onClick={() => onPick(ch)}
                    style={{ padding: '8px 10px', borderRadius: 6, border: '1px solid var(--bd)', background: 'var(--bg)',
                      marginBottom: 6, cursor: 'pointer', transition: 'border-color .12s' }}
                    onMouseEnter={e => e.currentTarget.style.borderColor = CAT_COLORS[ch._category]}
                    onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--bd)'}>
                    <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--tx)' }}>{ch.title}</div>
                    <div style={{ fontSize: 10, color: 'var(--txD)', marginTop: 2 }}>{ch.description}</div>
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ── SlotGrid — flat grid of slots, no category labels ─────────────────────────
export function SlotGrid({ slots, onSlotDrop, onSlotClick, onRemove, onExpand, onToggleWide, onResize, onEditCustom, dragOverId, investigatedIp, availableIps, globalTimeBounds, timeline, timeRange, bucketSec, setBucketSec }) {
  // Flatten all category slots into one list, preserving id/chart/wide
  const allSlots = CAT_ORDER.flatMap(cat => slots[cat] || []);

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
      {allSlots.map(slot => {
        const isWide = slot.wide;
        return (
          <div key={slot.id} style={{ gridColumn: isWide ? '1 / -1' : 'auto' }}>
            {slot.chart ? (
              <div style={{ border: '1px solid var(--bd)', borderRadius: 8, overflow: 'hidden', background: 'var(--bgP)' }}>
                <PlacedCard
                  chart={slot.chart}
                  investigatedIp={investigatedIp}
                  availableIps={availableIps}
                  globalTimeBounds={globalTimeBounds}
                  timeline={timeline}
                  timeRange={timeRange}
                  bucketSec={bucketSec}
                  setBucketSec={setBucketSec}
                  isWide={isWide}
                  onToggleWide={() => onToggleWide(slot.id)}
                  cardHeight={slot.height}
                  onResize={h => onResize(slot.id, h)}
                  onRemove={() => onRemove(slot.id)}
                  onExpand={() => onExpand(slot.chart)}
                  onEdit={slot.chart._isCustom ? () => onEditCustom(slot.id, slot.chart) : undefined}
                  slotId={slot.id}
                />
              </div>
            ) : (
              <EmptySlot
                slotId={slot.id}
                dragOverId={dragOverId}
                onDrop={onSlotDrop}
                onClick={() => onSlotClick(slot.id)}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── PaletteCategory — collapsible category section in the right palette ───────
export function PaletteCategory({ category, charts, onDragStart, onDragEnd }) {
  const [collapsed, setCollapsed] = useState(false);
  const color = CAT_COLORS[category];
  const label = CAT_LABELS[category];
  const isAlerts = category === 'alerts';

  return (
    <div style={{ marginBottom: 14 }}>
      <div
        onClick={() => setCollapsed(v => !v)}
        style={{ display: 'flex', alignItems: 'center', gap: 4, margin: '6px 0 4px 2px', cursor: 'pointer', userSelect: 'none' }}
      >
        <span style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: '.08em', color, flex: 1 }}>{label}</span>
        <span style={{ fontSize: 9, color: 'var(--txD)' }}>{collapsed ? '▶' : '▼'}</span>
      </div>
      {!collapsed && (
        isAlerts ? (
          <div style={{ fontSize: 9, color: 'var(--txD)', fontStyle: 'italic', padding: '4px 6px' }}>Coming soon</div>
        ) : (
          <>
            {charts.map(chart => (
              <div
                key={chart.name}
                draggable
                onDragStart={() => onDragStart(chart)}
                onDragEnd={onDragEnd}
                style={{
                  padding: '6px 8px', borderRadius: 6, border: '1px solid var(--bd)',
                  background: 'var(--bgP)', marginBottom: 5, cursor: 'grab',
                  transition: 'border-color .12s',
                }}
                onMouseEnter={e => e.currentTarget.style.borderColor = color}
                onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--bd)'}
              >
                <div style={{ fontSize: 11, fontWeight: 500, color: 'var(--tx)' }}>{chart.title}</div>
                <div style={{ fontSize: 9, color: 'var(--txD)', marginTop: 2, lineHeight: 1.3 }}>{chart.description}</div>
              </div>
            ))}
          </>
        )
      )}
    </div>
  );
}
