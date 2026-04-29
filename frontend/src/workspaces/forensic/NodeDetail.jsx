import { useState, useCallback, useEffect, useMemo } from 'react';
import Tag from '../../core/components/Tag';
import Row from '../../core/components/Row';
import Collapse from '../../core/components/Collapse';
import { GenericDisplay } from '../../core/components/PluginSection';
import { useWorkspace } from '@/WorkspaceProvider';

// ── Helpers ───────────────────────────────────────────────────────────────────

function copyToClipboard(text) {
  try { navigator.clipboard.writeText(text); } catch { /* ignore */ }
}

function CopyBtn({ text }) {
  const [copied, setCopied] = useState(false);
  const handleClick = (e) => {
    e.stopPropagation();
    copyToClipboard(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  };
  return (
    <button
      onClick={handleClick}
      title="Copy"
      style={{
        background: 'none', border: 'none', cursor: 'pointer', padding: '1px 4px',
        color: copied ? 'var(--acG)' : 'var(--txD)', fontSize: 9, flexShrink: 0,
        lineHeight: 1,
      }}
    >{copied ? '✓' : '⎘'}</button>
  );
}

// Monospace expandable block — for command lines
function CmdBlock({ label, value }) {
  const [expanded, setExpanded] = useState(false);
  if (!value) return null;
  const isLong = value.length > 120;
  const display = (!isLong || expanded) ? value : value.slice(0, 120) + '…';
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{
        fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase',
        letterSpacing: '.05em', marginBottom: 3,
        display: 'flex', alignItems: 'center', gap: 4,
      }}>
        {label}
        <CopyBtn text={value} />
      </div>
      <div
        style={{
          fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--txM)',
          background: 'var(--bgC)', border: '1px solid var(--bd)',
          borderRadius: 4, padding: '5px 8px', wordBreak: 'break-all',
          lineHeight: 1.5, whiteSpace: 'pre-wrap',
        }}
      >{display}</div>
      {isLong && (
        <button
          onClick={() => setExpanded(x => !x)}
          style={{
            background: 'none', border: 'none', cursor: 'pointer',
            fontSize: 9, color: 'var(--ac)', padding: '2px 0', marginTop: 2,
          }}
        >{expanded ? 'Show less' : 'Show full'}</button>
      )}
    </div>
  );
}

// Parse "SHA256=abc,MD5=def" → [{k,v}]
function parseHashes(raw) {
  if (!raw || typeof raw !== 'string') return [];
  return raw.split(',').map(part => {
    const eq = part.indexOf('=');
    if (eq < 1) return null;
    return { k: part.slice(0, eq).trim(), v: part.slice(eq + 1).trim() };
  }).filter(Boolean);
}

function HashBlock({ value }) {
  const pairs = useMemo(() => parseHashes(value), [value]);
  if (!pairs.length) return null;
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{
        fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase',
        letterSpacing: '.05em', marginBottom: 3,
      }}>Hashes</div>
      {pairs.map(({ k, v }) => (
        <div key={k} style={{
          display: 'flex', alignItems: 'flex-start', gap: 4,
          marginBottom: 3,
        }}>
          <span style={{
            fontSize: 9, color: 'var(--txD)', minWidth: 54,
            flexShrink: 0, paddingTop: 1, textTransform: 'uppercase',
            letterSpacing: '.03em',
          }}>{k}</span>
          <span style={{
            fontFamily: 'var(--fn)', fontSize: 9, color: 'var(--txM)',
            wordBreak: 'break-all', lineHeight: 1.5, flex: 1,
          }}>{v}</span>
          <CopyBtn text={v} />
        </div>
      ))}
    </div>
  );
}

// Integrity level badge
const INTEGRITY_COLORS = {
  system:  '#a371f7',
  high:    '#f85149',
  medium:  '#d29922',
  low:     '#3fb950',
};
function IntegrityBadge({ value }) {
  if (!value) return null;
  const key = value.toLowerCase();
  const color = INTEGRITY_COLORS[key] || '#8b949e';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
      <span style={{ fontSize: 9, color: 'var(--txD)', minWidth: 90, flexShrink: 0 }}>Integrity</span>
      <span style={{
        fontSize: 9, padding: '1px 7px', borderRadius: 8, fontWeight: 600,
        background: color + '22', color, border: '1px solid ' + color + '44',
        textTransform: 'capitalize',
      }}>{value}</span>
    </div>
  );
}

// ── Per-type field renderers ───────────────────────────────────────────────────

function ProcessDetail({ node }) {
  return (
    <>
      {node.image        && <Row l="Image"    v={node.image} />}
      {node.user         && <Row l="User"     v={node.user} />}
      {node.pid != null  && <Row l="PID"      v={String(node.pid)} />}
      {node.guid         && <Row l="GUID"     v={node.guid} />}
      {node.computer     && <Row l="Computer" v={node.computer} />}
      {node.integrity_level && <IntegrityBadge value={node.integrity_level} />}
    </>
  );
}

function FileDetail({ node }) {
  return (
    <>
      {node.path      && <Row l="Path"      v={node.path} />}
      {node.extension && <Row l="Extension" v={node.extension} />}
    </>
  );
}

function RegistryDetail({ node }) {
  return (
    <>
      {node.key  && <Row l="Key"  v={node.key} />}
      {node.hive && <Row l="Hive" v={node.hive} />}
    </>
  );
}

function EndpointDetail({ node }) {
  return (
    <>
      {node.ip          && <Row l="IP"       v={node.ip} />}
      {node.port != null && <Row l="Port"    v={String(node.port)} />}
      {node.hostname    && <Row l="Hostname" v={node.hostname} />}
    </>
  );
}

// ── Plugin sections ───────────────────────────────────────────────────────────

function ForensicPluginSections({ nodeId, pluginResults, uiSlots }) {
  if (!pluginResults || !uiSlots || uiSlots.length === 0) return null;
  const nodeSlots = uiSlots
    .filter(s => s.slot_type === 'node_detail_section')
    .sort((a, b) => a.priority - b.priority);
  return nodeSlots.map(slot => {
    const nodeData = pluginResults?.[slot.plugin]?.[nodeId];
    if (!nodeData?._display || nodeData._display.length === 0) return null;
    return (
      <Collapse key={`${slot.plugin}.${slot.slot_id}`} title={slot.title} open={slot.default_open}>
        <GenericDisplay display={nodeData._display} />
      </Collapse>
    );
  });
}

// ── Connections ───────────────────────────────────────────────────────────────

function ConnectionsSection({ nodeId, edges = [], nodes = [], onSelectEdge, schema }) {
  const edgeMetaByName = useMemo(() => {
    const m = {};
    for (const et of (schema?.edge_types || [])) m[et.name] = et;
    return m;
  }, [schema]);

  const connected = useMemo(() => edges.filter(e => {
    const s = typeof e.source === 'object' ? e.source.id : e.source;
    const t = typeof e.target === 'object' ? e.target.id : e.target;
    return s === nodeId || t === nodeId;
  }), [edges, nodeId]);

  if (!connected.length) return null;

  return (
    <Collapse title={`Connections (${connected.length})`} open>
      {connected.map((e, i) => {
        const s = typeof e.source === 'object' ? e.source.id : e.source;
        const t = typeof e.target === 'object' ? e.target.id : e.target;
        const isOut = s === nodeId;
        const otherId = isOut ? t : s;
        const otherNode = nodes.find(n => n.id === otherId);
        const otherLabel = otherNode?.label || otherNode?.image || otherId;
        const em = edgeMetaByName[e.type] || null;
        const count = e.event_count || e.count || 0;
        return (
          <div
            key={e.id || i}
            className="hr"
            onClick={() => onSelectEdge?.(e)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '5px 2px', borderBottom: '1px solid var(--bd)',
              cursor: 'pointer', borderRadius: 3, fontSize: 10,
            }}
          >
            <span style={{ fontSize: 9, color: 'var(--txD)', flexShrink: 0, width: 10 }}>
              {isOut ? '→' : '←'}
            </span>
            {em
              ? <Tag color={em.color} small>{em.label || e.type}</Tag>
              : <span style={{ fontSize: 9, color: 'var(--txD)' }}>{e.type}</span>
            }
            <span style={{
              flex: 1, color: 'var(--txM)', overflow: 'hidden',
              textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>{otherLabel}</span>
            {count > 0 && (
              <span style={{ fontSize: 9, color: 'var(--txD)', flexShrink: 0 }}>
                {count} ev
              </span>
            )}
          </div>
        );
      })}
    </Collapse>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function ForensicNodeDetail({
  nodeId, nodes = [], edges = [], onClear,
  onSelectEdge, pluginResults, uiSlots,
  annotations = [], onSaveNote,
}) {
  const workspace = useWorkspace();
  const node = nodes.find(n => n.id === nodeId);

  // Schema-driven type metadata — no local TYPE_META constant
  const nodeTypeMeta = useMemo(() => {
    const nt = (workspace.schema?.node_types || []).find(t => t.name === node?.type);
    return nt || { color: 'var(--ac)', label: node?.type || 'Node' };
  }, [workspace.schema, node?.type]);

  // Notes
  const existingNote = annotations.find(a => a.annotation_type === 'note' && a.node_id === nodeId);
  const [noteText, setNoteText] = useState(existingNote?.text || '');
  const [noteSaved, setNoteSaved] = useState(false);
  useEffect(() => {
    const note = annotations.find(a => a.annotation_type === 'note' && a.node_id === nodeId);
    setNoteText(note?.text || '');
    setNoteSaved(false);
  }, [nodeId, annotations]);
  const saveNote = useCallback(async () => {
    if (onSaveNote) {
      await onSaveNote(nodeId, noteText, existingNote?.id);
      setNoteSaved(true);
      setTimeout(() => setNoteSaved(false), 1500);
    }
  }, [nodeId, noteText, existingNote, onSaveNote]);

  if (!node) return null;

  const color = nodeTypeMeta.color;
  const typeLabel = nodeTypeMeta.label || node.type || 'Node';
  const primaryLabel = node.label || node.image || node.id;
  const eventCount = node.event_count ?? null;

  // Command line and hashes come from the node directly (aggregated from events)
  const cmdLine = node.command_line || null;
  const hashes  = node.hashes || null;

  return (
    <div className="fi" style={{ padding: 16, overflowY: 'auto', height: '100%' }}>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <div className="sh" style={{ marginBottom: 0 }}>Node Detail</div>
        <button className="btn" onClick={onClear}>✕</button>
      </div>

      {/* Primary label */}
      <div style={{
        fontSize: 13, fontWeight: 600, marginBottom: 8,
        wordBreak: 'break-all', color: 'var(--tx)', lineHeight: 1.4,
      }}>
        {primaryLabel}
      </div>

      {/* Type + event count badges */}
      <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 12 }}>
        <Tag color={color}>{typeLabel}</Tag>
        {eventCount != null && (
          <Tag color="#8b949e">{eventCount} event{eventCount !== 1 ? 's' : ''}</Tag>
        )}
        {node.child_count > 0 && (
          <Tag color="#4fc3f7" small>{node.child_count} child{node.child_count !== 1 ? 'ren' : ''}</Tag>
        )}
        {node.connection_count > 0 && (
          <Tag color="#ce93d8" small>{node.connection_count} connection{node.connection_count !== 1 ? 's' : ''}</Tag>
        )}
      </div>

      {/* Per-type identity fields */}
      {node.type === 'process'  && <ProcessDetail  node={node} />}
      {node.type === 'file'     && <FileDetail     node={node} />}
      {node.type === 'registry' && <RegistryDetail node={node} />}
      {node.type === 'endpoint' && <EndpointDetail node={node} />}

      {/* Command line (process) */}
      {node.type === 'process' && <CmdBlock label="Command Line" value={cmdLine} />}

      {/* Hashes (process) */}
      {node.type === 'process' && <HashBlock value={hashes} />}

      {/* Connections */}
      <ConnectionsSection
        nodeId={nodeId}
        edges={edges}
        nodes={nodes}
        onSelectEdge={onSelectEdge}
        schema={workspace.schema}
      />

      {/* Plugin classifier sections */}
      <ForensicPluginSections nodeId={nodeId} pluginResults={pluginResults} uiSlots={uiSlots} />

      {/* Entity ID */}
      <Collapse title="Entity ID">
        <div style={{ fontFamily: 'var(--fn)', fontSize: 9, color: 'var(--txD)', wordBreak: 'break-all', lineHeight: 1.6 }}>
          {node.id}
        </div>
      </Collapse>

      {/* Notes */}
      <Collapse title="Notes" open={!!noteText}>
        <textarea
          value={noteText}
          onChange={e => setNoteText(e.target.value)}
          placeholder="Add investigation notes…"
          rows={3}
          style={{
            width: '100%', boxSizing: 'border-box',
            background: 'var(--bgC)', border: '1px solid var(--bd)', borderRadius: 4,
            padding: '6px 8px', fontSize: 10, color: 'var(--txM)',
            fontFamily: 'inherit', resize: 'vertical', outline: 'none', lineHeight: 1.5,
          }}
        />
        <button
          className="btn"
          onClick={saveNote}
          style={{
            fontSize: 9, padding: '2px 12px', marginTop: 5, width: '100%',
            background: noteSaved ? 'rgba(63,185,80,.15)' : undefined,
            color: noteSaved ? 'var(--acG)' : undefined,
            borderColor: noteSaved ? 'var(--acG)' : undefined,
          }}
        >{noteSaved ? '✓ Saved' : 'Save note'}</button>
      </Collapse>

    </div>
  );
}
