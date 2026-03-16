import React from 'react';
import Collapse from './Collapse';
import Row from './Row';
import Tag from './Tag';

/**
 * Generic renderer for plugin _display data.
 *
 * Plugins return data with a "_display" list of typed elements:
 *   {type: "row",   label, value}
 *   {type: "tags",  items: [{text, color}, ...]}
 *   {type: "list",  items: [{label, value}, ...], clickable?}
 *   {type: "text",  value, color?}
 *   {type: "table", headers: [...], rows: [[...], ...]}
 *
 * Analysis developers only write Python — no frontend code needed.
 */
export default function PluginSection({ display, onClickItem }) {
  if (!display || !Array.isArray(display) || display.length === 0) return null;

  return (
    <div>
      {display.map((item, i) => {
        if (!item?.type) return null;

        switch (item.type) {
          case 'row':
            return <Row key={i} l={item.label} v={item.value} />;

          case 'tags':
            return (
              <div key={i} style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 4 }}>
                {(item.items || []).map((t, j) => (
                  <Tag key={j} color={t.color || '#8b949e'}>{t.text}</Tag>
                ))}
              </div>
            );

          case 'list':
            return (
              <div key={i} style={{ marginBottom: 4 }}>
                {(item.items || []).map((li, j) => (
                  <div key={j}
                    className={item.clickable ? 'hr' : ''}
                    onClick={item.clickable && onClickItem ? () => onClickItem(li.label) : undefined}
                    style={{
                      display: 'flex', justifyContent: 'space-between',
                      fontSize: 10, padding: '3px 4px',
                      borderBottom: '1px solid var(--bd)',
                      cursor: item.clickable ? 'pointer' : 'default',
                      borderRadius: 3,
                    }}>
                    <span style={{ color: 'var(--txM)' }}>{li.label}</span>
                    <span style={{ color: 'var(--txD)' }}>{li.value}</span>
                  </div>
                ))}
              </div>
            );

          case 'text':
            return (
              <div key={i} style={{
                fontSize: 9, color: item.color || 'var(--txD)',
                marginTop: 2, marginBottom: 4,
              }}>
                {item.value}
              </div>
            );

          case 'table':
            return (
              <div key={i} style={{ marginBottom: 6, overflowX: 'auto' }}>
                <table style={{
                  width: '100%', borderCollapse: 'collapse',
                  fontSize: 10, fontFamily: 'var(--fn)',
                }}>
                  {item.headers && (
                    <thead>
                      <tr>
                        {item.headers.map((h, j) => (
                          <th key={j} style={{
                            textAlign: 'left', padding: '3px 6px',
                            borderBottom: '1px solid var(--bd)',
                            color: 'var(--txM)', fontWeight: 600,
                            fontSize: 9, textTransform: 'uppercase',
                            letterSpacing: '.05em',
                          }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                  )}
                  <tbody>
                    {(item.rows || []).map((row, j) => (
                      <tr key={j} className="hr">
                        {row.map((cell, k) => (
                          <td key={k} style={{
                            padding: '3px 6px',
                            borderBottom: '1px solid var(--bd)',
                            color: 'var(--tx)',
                          }}>{cell}</td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            );

          default:
            return null;
        }
      })}
    </div>
  );
}


/**
 * PluginSlot — wraps a plugin section in a Collapse with the slot title.
 *
 * If dedicatedRenderer is provided, it renders that (custom UI).
 * Otherwise renders _display generically.
 */
export function PluginSlot({ slot, data, onClickItem, dedicatedRenderer }) {
  if (!data) return null;

  if (dedicatedRenderer) {
    return (
      <Collapse title={slot.title} open={slot.default_open}>
        {dedicatedRenderer}
      </Collapse>
    );
  }

  const display = data._display;
  if (!display || !Array.isArray(display) || display.length === 0) return null;

  return (
    <Collapse title={slot.title} open={slot.default_open}>
      <PluginSection display={display} onClickItem={onClickItem} />
    </Collapse>
  );
}


/**
 * GenericDisplay — renders a _display array inline (no Collapse wrapper).
 * Used inside dedicated renderers as a fallback when they get data
 * in an unexpected shape but _display is present.
 */
export function GenericDisplay({ display, onClickItem }) {
  return <PluginSection display={display} onClickItem={onClickItem} />;
}


/**
 * PluginSections — renders all plugin slots of a given type.
 *
 * For each slot matching slotType:
 *   - If a dedicated renderer exists in the `dedicated` map, use it
 *   - Otherwise render generically from _display
 *
 * Props:
 *   slotType: "stats_section", "node_detail_section", etc.
 *   pluginResults: the full pluginResults object from App state
 *   uiSlots: the pluginSlots array from App state
 *   dedicated: { "pluginName.slotId": ReactComponent } map of dedicated renderers
 *   onSelectNode: optional click handler for clickable list items
 */
export function PluginSections({ slotType, pluginResults, uiSlots, dedicated = {}, onSelectNode }) {
  if (!uiSlots || !pluginResults) return null;

  const slots = uiSlots
    .filter(s => s.slot_type === slotType)
    .sort((a, b) => a.priority - b.priority);

  if (slots.length === 0) return null;

  return (
    <>
      {slots.map(slot => {
        const key = `${slot.plugin}.${slot.slot_id}`;
        const data = pluginResults?.[slot.plugin]?.[slot.slot_id];
        if (!data) return null;

        const DedicatedRenderer = dedicated[key];
        if (DedicatedRenderer) {
          // Dedicated renderers handle null data themselves (e.g. "no data available" messages)
          return (
            <Collapse key={key} title={slot.title} open={slot.default_open}>
              <DedicatedRenderer data={data} onSelectNode={onSelectNode} />
            </Collapse>
          );
        }

        // Generic: render from _display — skip silently if no data
        if (!data) return null;
        const display = data._display;
        if (!display || !Array.isArray(display) || display.length === 0) return null;

        return (
          <Collapse key={key} title={slot.title} open={slot.default_open}>
            <PluginSection display={display} onClickItem={onSelectNode} />
          </Collapse>
        );
      })}
    </>
  );
}
