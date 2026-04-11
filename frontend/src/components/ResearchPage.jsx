import React, { useState, useEffect, useRef } from 'react';
import { fetchResearchCharts } from '../api';
import { fTtime } from '../utils';
import Sparkline from './Sparkline';
import { loadSavedCustomCharts, saveCustomCharts } from './research/customChartPersistence';
import CustomChartBuilder from './research/CustomChartBuilder';
import { ExpandedOverlay } from './research/PlacedCard';
import { inferCategory, CAT_ORDER, SlotGrid, ChartPicker, PaletteCategory } from './research/ResearchSlotBoard';

// ── ResearchPage ──────────────────────────────────────────────────────────────
export default function ResearchPage({
  investigatedIp = '',
  searchIp = '',
  seqAckSessionId = '',
  availableIps = [],
  timeline = [], timeRange = [0, 0], setTimeRange,
  bucketSec = 15, setBucketSec,
}) {
  const effectiveIp = investigatedIp || searchIp;

  const [allCharts, setAllCharts] = useState([]);
  const [loadErr, setLoadErr]     = useState('');

  const [slots, setSlots] = useState({
    host:    [{ id: 'host-0', chart: null, wide: false, height: null }, { id: 'host-1', chart: null, wide: false, height: null }],
    session: [{ id: 'session-0', chart: null, wide: false, height: null }, { id: 'session-1', chart: null, wide: false, height: null }],
    capture: [{ id: 'capture-0', chart: null, wide: false, height: null }, { id: 'capture-1', chart: null, wide: false, height: null }],
    alerts:  [],
  });

  const [draggedChart, setDraggedChart] = useState(null);
  const [dragOverId, setDragOverId]     = useState(null);
  const [pickerSlotId, setPickerSlotId] = useState(null);
  const [expandedChart, setExpandedChart] = useState(null);
  const [paletteOpen, setPaletteOpen]   = useState(true);
  const slotCounter = useRef(100); // start above default slot IDs to avoid collisions

  // ── Custom chart builder state ────────────────────────────────────────────
  // builderState: null (closed) | { mode: 'create', slotId } | { mode: 'edit', slotId, initial }
  const [builderState, setBuilderState] = useState(null);

  const timeRangeRef = useRef(timeRange);
  const timelineRef  = useRef(timeline);
  useEffect(() => { timeRangeRef.current = timeRange; }, [timeRange]);
  useEffect(() => { timelineRef.current  = timeline;  }, [timeline]);

  function globalTimeBounds() {
    const tl = timelineRef.current;
    const tr = timeRangeRef.current;
    if (!tl.length) return { timeStart: null, timeEnd: null };
    return { timeStart: tl[tr[0]]?.start_time ?? null, timeEnd: tl[tr[1]]?.end_time ?? null };
  }

  useEffect(() => {
    fetchResearchCharts()
      .then(d => {
        const charts = (d.charts || [])
          .filter(c => c.name !== 'session_gantt')
          .map(c => ({ ...c, _category: inferCategory(c) }));
        setAllCharts(charts);

        if (seqAckSessionId) {
          const seqChart = charts.find(c => c.name === 'seq_ack_timeline');
          if (seqChart) {
            setSlots(prev => placeChart(prev, 'session-0', seqChart));
          }
        }
      })
      .catch(e => setLoadErr(e.message));
  }, []);

  function placeChart(prevSlots, slotId, chart) {
    const next = {};
    for (const [cat, arr] of Object.entries(prevSlots)) {
      next[cat] = arr.map(s => s.id === slotId ? { ...s, chart } : s);
    }
    return next;
  }

  // Build a chart object from a custom config (returned by CustomChartBuilder)
  function makeCustomChart(config) {
    return {
      name:           `custom_${Date.now()}`,
      title:          config.title || 'Custom Chart',
      description:    `${config.source} · ${config.chart_type} · ${config.x_field}${config.y_field ? ' vs ' + config.y_field : ''}`,
      params:         [],
      _isCustom:      true,
      _customConfig:  config,
      _category:      'capture',
    };
  }

  // Save custom chart config to localStorage
  function persistCustomConfig(config) {
    const saved = loadSavedCustomCharts();
    const existing = saved.findIndex(c => c._id === config._id);
    if (existing >= 0) saved[existing] = config;
    else saved.push(config);
    saveCustomCharts(saved);
  }

  function removeCustomConfig(id) {
    const saved = loadSavedCustomCharts().filter(c => c._id !== id);
    saveCustomCharts(saved);
  }

  function handleBuilderSave(config) {
    const bs = builderState;
    setBuilderState(null);
    if (!bs) return;
    // Give it a stable ID for localStorage keying
    const configWithId = { ...config, _id: bs.initial?._id || `cc_${Date.now()}` };
    persistCustomConfig(configWithId);
    const chart = makeCustomChart(configWithId);
    if (bs.mode === 'create') {
      // Place into a new slot if no target, or into specific slot from picker
      const targetSlotId = bs.slotId;
      if (targetSlotId) {
        setSlots(prev => placeChart(prev, targetSlotId, chart));
      } else {
        // Add new slot and place
        const id = `slot-${slotCounter.current++}`;
        setSlots(prev => ({
          ...prev,
          capture: [...prev.capture, { id, chart, wide: false, height: null }],
        }));
      }
    } else {
      // Edit: replace existing slot's chart in-place
      setSlots(prev => placeChart(prev, bs.slotId, chart));
    }
  }

  function handleEditCustom(slotId, existingChart) {
    setBuilderState({ mode: 'edit', slotId, initial: existingChart._customConfig });
  }

  function addSlot() {
    const id = `slot-${slotCounter.current++}`;
    setSlots(prev => ({ ...prev, capture: [...prev.capture, { id, chart: null, wide: false, height: null }] }));
  }

  function handleResize(slotId, height) {
    setSlots(prev => {
      const next = {};
      for (const [cat, arr] of Object.entries(prev)) {
        next[cat] = arr.map(s => s.id === slotId ? { ...s, height } : s);
      }
      return next;
    });
  }

  function handleSlotDrop(action, slotId) {
    if (action === 'over')  { setDragOverId(slotId); return; }
    if (action === 'leave') { setDragOverId(null); return; }
    if (action === 'drop' && draggedChart) {
      setSlots(prev => placeChart(prev, slotId, draggedChart));
      setDraggedChart(null);
      setDragOverId(null);
    }
  }

  function handleSlotClick(slotId) {
    setPickerSlotId(slotId);
  }

  function handlePickerPick(chart) {
    setSlots(prev => placeChart(prev, pickerSlotId, chart));
    setPickerSlotId(null);
  }

  function handleRemove(slotId) {
    setSlots(prev => {
      const next = {};
      for (const [cat, arr] of Object.entries(prev)) {
        next[cat] = arr.map(s => s.id === slotId ? { ...s, chart: null } : s);
      }
      return next;
    });
  }

  function handleToggleWide(slotId) {
    setSlots(prev => {
      const next = {};
      for (const [cat, arr] of Object.entries(prev)) {
        next[cat] = arr.map(s => {
          if (s.id !== slotId) return s;
          const newWide = !s.wide;
          return { ...s, wide: newWide, height: newWide ? s.height : null };
        });
      }
      return next;
    });
  }

  function paletteCharts(cat) {
    return allCharts.filter(c => c._category === cat);
  }

  const timeLabel = (() => {
    if (!timeline.length) return 'Full capture';
    const s = timeline[timeRange[0]], e = timeline[timeRange[1]];
    return s && e ? `${fTtime(s.start_time)} — ${fTtime(e.end_time)}` : 'Full capture';
  })();
  const isFullRange = !timeline.length || (timeRange[0] === 0 && timeRange[1] === timeline.length - 1);

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden', position: 'relative', background: 'var(--bg)' }}>

      {/* Main canvas */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px 20px', display: 'flex', flexDirection: 'column', gap: 24 }}>

        {/* Global time scope */}
        {timeline.length > 1 && (
          <div style={{ background: 'var(--bgP)', border: '1px solid var(--bd)', borderRadius: 8, padding: '10px 14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="var(--txD)" strokeWidth="2">
                  <circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>
                </svg>
                <span style={{ fontSize: 9, color: 'var(--txM)', textTransform: 'uppercase', letterSpacing: '.06em' }}>Global time scope</span>
                {[5, 15, 30, 60].map(s => (
                  <button key={s} className={'btn' + (bucketSec === s ? ' on' : '')}
                    onClick={() => setBucketSec(s)} style={{ padding: '1px 5px', fontSize: 9 }}>{s}s</button>
                ))}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 9, color: isFullRange ? 'var(--txD)' : 'var(--ac)', fontFamily: 'var(--fn)' }}>{timeLabel}</span>
                {!isFullRange && (
                  <button className="btn" style={{ fontSize: 9, padding: '1px 6px' }}
                    onClick={() => setTimeRange([0, timeline.length - 1])}>Reset</button>
                )}
              </div>
            </div>
            <Sparkline data={timeline} width={600} height={20} activeRange={timeRange} />
            <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 6 }}>
              <span style={{ fontSize: 9, color: 'var(--txD)', minWidth: 30 }}>Start</span>
              <input type="range" min={0} max={timeline.length - 1} value={timeRange[0]}
                onChange={e => { const v = +e.target.value; setTimeRange([v, Math.max(v, timeRange[1])]); }}
                style={{ flex: 1 }} />
            </div>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 2 }}>
              <span style={{ fontSize: 9, color: 'var(--txD)', minWidth: 30 }}>End</span>
              <input type="range" min={0} max={timeline.length - 1} value={timeRange[1]}
                onChange={e => { const v = +e.target.value; setTimeRange([Math.min(timeRange[0], v), v]); }}
                style={{ flex: 1 }} />
            </div>
            <div style={{ marginTop: 6, fontSize: 9, color: 'var(--txD)' }}>
              Per-card filters override this scope. Cards set to "global" inherit this range.
            </div>
          </div>
        )}

        {loadErr && (
          <div style={{ padding: '10px 14px', background: 'rgba(248,81,73,.08)', border: '1px solid rgba(248,81,73,.2)', borderRadius: 8, color: 'var(--acR)', fontSize: 11 }}>
            Failed to load charts: {loadErr}
          </div>
        )}

        {/* Flat slot grid — no category labels */}
        <SlotGrid
          slots={slots}
          onSlotDrop={handleSlotDrop}
          onSlotClick={handleSlotClick}
          onRemove={handleRemove}
          onExpand={setExpandedChart}
          onToggleWide={handleToggleWide}
          onResize={handleResize}
          onEditCustom={handleEditCustom}
          dragOverId={dragOverId}
          investigatedIp={effectiveIp}
          availableIps={availableIps}
          globalTimeBounds={globalTimeBounds()}
          timeline={timeline}
          timeRange={timeRange}
          bucketSec={bucketSec}
          setBucketSec={setBucketSec}
        />
        <div style={{ display: 'flex', justifyContent: 'center' }}>
          <button className="btn" onClick={addSlot}
            style={{ fontSize: 10, padding: '5px 20px', color: 'var(--txD)', borderColor: 'var(--bd)' }}>
            + add slot
          </button>
        </div>
      </div>

      {/* Right palette */}
      <div style={{
        width: paletteOpen ? 200 : 28, flexShrink: 0, borderLeft: '1px solid var(--bd)',
        background: '#0a0b0f', display: 'flex', flexDirection: 'column', overflow: 'hidden',
        transition: 'width .15s ease',
      }}>
        {/* Palette header */}
        <div style={{ padding: '10px 8px 6px', display: 'flex', alignItems: 'center', borderBottom: '1px solid var(--bd)', flexShrink: 0, gap: 6 }}>
          {paletteOpen && (
            <span style={{ flex: 1, fontSize: 9, textTransform: 'uppercase', letterSpacing: '.1em', color: 'var(--txD)' }}>Charts</span>
          )}
          <button
            onClick={() => setPaletteOpen(v => !v)}
            title={paletteOpen ? 'Collapse palette' : 'Expand palette'}
            style={{ width: 18, height: 18, borderRadius: 3, border: '1px solid var(--bd)', background: 'transparent',
              color: 'var(--txD)', cursor: 'pointer', fontSize: 9, display: 'flex', alignItems: 'center', justifyContent: 'center',
              flexShrink: 0 }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--ac)'; e.currentTarget.style.color = 'var(--ac)'; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--bd)'; e.currentTarget.style.color = 'var(--txD)'; }}
          >
            {paletteOpen ? '›' : '‹'}
          </button>
        </div>

        {/* Palette content */}
        {paletteOpen && (
          <div style={{ flex: 1, overflowY: 'auto', padding: '8px 8px' }}>
            {/* Custom chart button — at top of palette */}
            <div style={{ marginBottom: 12 }}>
              <button
                onClick={() => setBuilderState({ mode: 'create', slotId: null })}
                style={{
                  width: '100%', padding: '7px 8px', borderRadius: 6, cursor: 'pointer',
                  border: '1px dashed var(--acP)', background: 'rgba(163,113,247,.06)',
                  color: 'var(--acP)', fontSize: 10, fontWeight: 600, textAlign: 'left',
                  display: 'flex', alignItems: 'center', gap: 6,
                }}
                onMouseEnter={e => { e.currentTarget.style.background = 'rgba(163,113,247,.14)'; }}
                onMouseLeave={e => { e.currentTarget.style.background = 'rgba(163,113,247,.06)'; }}
              >
                <span style={{ fontSize: 13 }}>✦</span> Custom chart
              </button>
            </div>
            {CAT_ORDER.map(cat => (
              <PaletteCategory
                key={cat}
                category={cat}
                charts={paletteCharts(cat)}
                onDragStart={setDraggedChart}
                onDragEnd={() => setDraggedChart(null)}
              />
            ))}
          </div>
        )}
      </div>

      {/* Chart picker modal */}
      {pickerSlotId && (
        <ChartPicker
          charts={allCharts}
          onPick={handlePickerPick}
          onClose={() => setPickerSlotId(null)}
          onCustom={() => {
            const sid = pickerSlotId;
            setPickerSlotId(null);
            setBuilderState({ mode: 'create', slotId: sid });
          }}
        />
      )}

      {/* Custom chart builder modal */}
      {builderState && (
        <CustomChartBuilder
          initial={builderState.initial || null}
          onSave={handleBuilderSave}
          onClose={() => setBuilderState(null)}
        />
      )}

      {/* Expanded overlay */}
      {expandedChart && (
        <ExpandedOverlay
          chart={expandedChart}
          investigatedIp={effectiveIp}
          availableIps={availableIps}
          globalTimeBounds={globalTimeBounds()}
          timeline={timeline}
          timeRange={timeRange}
          bucketSec={bucketSec}
          setBucketSec={setBucketSec}
          onClose={() => setExpandedChart(null)}
        />
      )}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
