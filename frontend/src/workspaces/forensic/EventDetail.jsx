import { useState, useCallback, useEffect, useMemo } from 'react';
import Tag from '../../core/components/Tag';
import Row from '../../core/components/Row';
import Collapse from '../../core/components/Collapse';
import { useWorkspace } from '@/WorkspaceProvider';

// ── Helpers ───────────────────────────────────────────────────────────────────

function copyToClipboard(text) {
  try { navigator.clipboard.writeText(text); } catch { /* ignore */ }
}

function CopyBtn({ text }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={e => { e.stopPropagation(); copyToClipboard(text); setCopied(true); setTimeout(() => setCopied(false), 1200); }}
      title="Copy"
      style={{
        background: 'none', border: 'none', cursor: 'pointer', padding: '1px 5px',
        color: copied ? 'var(--acG)' : 'var(--txD)', fontSize: 9, flexShrink: 0, lineHeight: 1,
      }}
    >{copied ? '✓' : '⎘'}</button>
  );
}

function actionLabel(at) {
  if (!at) return '';
  return at.split('_').map(s => s ? s[0].toUpperCase() + s.slice(1) : '').join(' ');
}

function formatTs(iso) {
  if (!iso) return '—';
  try { return new Date(iso).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC'); }
  catch { return iso; }
}

// Monospace expandable block for long strings
function CmdBlock({ value }) {
  const [expanded, setExpanded] = useState(false);
  if (!value) return null;
  const isLong = value.length > 160;
  const display = !isLong || expanded ? value : value.slice(0, 160) + '…';
  return (
    <div style={{ marginBottom: 4 }}>
      <div style={{
        fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--txM)',
        background: 'var(--bgC)', border: '1px solid var(--bd)',
        borderRadius: 4, padding: '6px 8px', wordBreak: 'break-all',
        lineHeight: 1.6, whiteSpace: 'pre-wrap',
      }}>{display}</div>
      {isLong && (
        <button
          onClick={() => setExpanded(x => !x)}
          style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 9, color: 'var(--ac)', padding: '2px 0' }}
        >{expanded ? 'Show less' : 'Show full'}</button>
      )}
    </div>
  );
}

function CmdField({ label, value }) {
  if (!value) return null;
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{
        fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase',
        letterSpacing: '.05em', marginBottom: 4,
        display: 'flex', alignItems: 'center', gap: 4,
      }}>
        {label} <CopyBtn text={value} />
      </div>
      <CmdBlock value={value} />
    </div>
  );
}

// Parse "SHA256=abc,MD5=def" → [{k,v}]
function parseHashes(raw) {
  if (!raw || typeof raw !== 'string') return [];
  return raw.split(',').map(part => {
    const eq = part.indexOf('=');
    return eq > 0 ? { k: part.slice(0, eq).trim(), v: part.slice(eq + 1).trim() } : null;
  }).filter(Boolean);
}

function HashRows({ value }) {
  const pairs = useMemo(() => parseHashes(value), [value]);
  if (!pairs.length) return null;
  return (
    <>
      {pairs.map(({ k, v }) => (
        <div key={k} style={{ display: 'flex', alignItems: 'flex-start', gap: 4, marginBottom: 4 }}>
          <span style={{
            fontSize: 9, color: 'var(--txD)', minWidth: 60, flexShrink: 0,
            textTransform: 'uppercase', letterSpacing: '.03em', paddingTop: 1,
          }}>{k}</span>
          <span style={{
            fontFamily: 'var(--fn)', fontSize: 9, color: 'var(--txM)',
            wordBreak: 'break-all', flex: 1, lineHeight: 1.6,
          }}>{v}</span>
          <CopyBtn text={v} />
        </div>
      ))}
    </>
  );
}

// Integrity badge
const INTEGRITY_COLORS = { system: '#a371f7', high: '#f85149', medium: '#d29922', low: '#3fb950' };
function IntegrityBadge({ value }) {
  if (!value) return null;
  const c = INTEGRITY_COLORS[value.toLowerCase()] || '#8b949e';
  return (
    <span style={{
      fontSize: 9, padding: '1px 7px', borderRadius: 8, fontWeight: 600,
      background: c + '22', color: c, border: '1px solid ' + c + '44',
      textTransform: 'capitalize',
    }}>{value}</span>
  );
}

// Initiated badge (network_connect)
function InitiatedBadge({ value }) {
  const text = value === 'true' || value === true ? 'Outbound' : value === 'false' || value === false ? 'Inbound' : null;
  if (!text) return null;
  const c = text === 'Outbound' ? '#3fb950' : '#f0883e';
  return (
    <span style={{
      fontSize: 9, padding: '1px 7px', borderRadius: 8, fontWeight: 600,
      background: c + '22', color: c, border: '1px solid ' + c + '44',
    }}>{text}</span>
  );
}

// Section label
function SectionLabel({ children }) {
  return (
    <div style={{
      fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase',
      letterSpacing: '.07em', fontWeight: 600,
      marginTop: 14, marginBottom: 6, paddingBottom: 4,
      borderBottom: '1px solid var(--bd)',
    }}>{children}</div>
  );
}

// ── Per-action-type content renderers ────────────────────────────────────────

function ProcessCreateContent({ fields }) {
  const f = fields || {};
  return (
    <>
      {/* Command Line — most important, shown first */}
      <CmdField label="Command Line" value={f.command_line} />

      {/* Process identity */}
      {(f.integrity_level || f.logon_id || f.terminal_session_id) && (
        <>
          <SectionLabel>Process</SectionLabel>
          {f.integrity_level && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
              <span style={{ fontSize: 9, color: 'var(--txD)', minWidth: 90, flexShrink: 0 }}>Integrity</span>
              <IntegrityBadge value={f.integrity_level} />
            </div>
          )}
          {f.logon_id           && <Row l="Logon ID"    v={f.logon_id} />}
          {f.terminal_session_id && <Row l="Session ID" v={f.terminal_session_id} />}
          {f.current_directory  && <Row l="Working Dir" v={f.current_directory} />}
        </>
      )}

      {/* Parent process */}
      {f.parent_command_line && (
        <>
          <SectionLabel>Parent Process</SectionLabel>
          <CmdField label="Parent Command Line" value={f.parent_command_line} />
        </>
      )}

      {/* Hashes */}
      {f.hashes && (
        <>
          <SectionLabel>Hashes</SectionLabel>
          <HashRows value={f.hashes} />
        </>
      )}

      {/* File metadata */}
      {(f.file_version || f.description || f.product || f.company || f.original_file_name) && (
        <>
          <SectionLabel>File Metadata</SectionLabel>
          {f.description       && <Row l="Description"    v={f.description} />}
          {f.product           && <Row l="Product"        v={f.product} />}
          {f.company           && <Row l="Company"        v={f.company} />}
          {f.file_version      && <Row l="File Version"   v={f.file_version} />}
          {f.original_file_name && <Row l="Original Name" v={f.original_file_name} />}
        </>
      )}

      {/* Rule */}
      {f.rule_name && (
        <>
          <SectionLabel>Detection</SectionLabel>
          <Row l="Rule" v={f.rule_name} />
        </>
      )}
    </>
  );
}

function NetworkConnectContent({ fields }) {
  const f = fields || {};
  return (
    <>
      <SectionLabel>Connection</SectionLabel>
      {f.protocol && <Row l="Protocol" v={f.protocol} />}
      {f.initiated != null && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
          <span style={{ fontSize: 9, color: 'var(--txD)', minWidth: 90, flexShrink: 0 }}>Direction</span>
          <InitiatedBadge value={f.initiated} />
        </div>
      )}
      {f.local_ip   && <Row l="Local IP"   v={`${f.local_ip}${f.local_port ? ':' + f.local_port : ''}`} />}
      {f.local_hostname && <Row l="Local Host" v={f.local_hostname} />}
      {f.local_port_name && <Row l="Local Port" v={f.local_port_name} />}
      {f.remote_port_name && <Row l="Remote Port" v={f.remote_port_name} />}
      {f.rule_name && (
        <>
          <SectionLabel>Detection</SectionLabel>
          <Row l="Rule" v={f.rule_name} />
        </>
      )}
    </>
  );
}

function FileCreateContent({ fields }) {
  const f = fields || {};
  return (
    <>
      {f.creation_utc_time && (
        <>
          <SectionLabel>Timestamps</SectionLabel>
          <Row l="Created (UTC)" v={f.creation_utc_time} />
        </>
      )}
      {f.hashes && (
        <>
          <SectionLabel>Hashes</SectionLabel>
          <HashRows value={f.hashes} />
        </>
      )}
      {f.rule_name && (
        <>
          <SectionLabel>Detection</SectionLabel>
          <Row l="Rule" v={f.rule_name} />
        </>
      )}
    </>
  );
}

function RegistrySetContent({ fields }) {
  const f = fields || {};
  return (
    <>
      {(f.details || f.event_type) && (
        <>
          <SectionLabel>Value</SectionLabel>
          {f.event_type && <Row l="Operation" v={f.event_type} />}
          {f.details && (
            <div style={{ marginBottom: 8 }}>
              <div style={{
                fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase',
                letterSpacing: '.05em', marginBottom: 4,
                display: 'flex', alignItems: 'center', gap: 4,
              }}>
                Data <CopyBtn text={f.details} />
              </div>
              <div style={{
                fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--txM)',
                background: 'var(--bgC)', border: '1px solid var(--bd)',
                borderRadius: 4, padding: '5px 8px', wordBreak: 'break-all', lineHeight: 1.5,
              }}>{f.details}</div>
            </div>
          )}
        </>
      )}
      {f.rule_name && (
        <>
          <SectionLabel>Detection</SectionLabel>
          <Row l="Rule" v={f.rule_name} />
        </>
      )}
    </>
  );
}

// Fallback: show all fields generically
function GenericContent({ fields }) {
  if (!fields || Object.keys(fields).length === 0) return null;
  return (
    <>
      {Object.entries(fields).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => (
        <Row key={k} l={k.replace(/_/g, ' ')} v={String(v)} />
      ))}
    </>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function ForensicEventDetail({
  event: ev,
  events = [],          // all events on the edge (for sibling nav)
  edgeContext = null,   // { srcLabel, dstLabel, edgeType, edgeColor } from EdgeDetail
  onBack,
  annotations = [],
  onSaveNote,
}) {
  const workspace = useWorkspace();

  // Sibling navigation
  const evIdx = events.findIndex(e => e === ev);
  const hasSibs = events.length > 1;
  const [navIdx, setNavIdx] = useState(evIdx >= 0 ? evIdx : 0);

  // Keep navIdx in sync if ev changes externally (e.g. edge changes)
  useEffect(() => {
    const i = events.findIndex(e => e === ev);
    setNavIdx(i >= 0 ? i : 0);
  }, [ev, events]);

  const currentEv = events[navIdx] || ev;

  // Schema edge color for action badge
  const edgeMetaByName = useMemo(() => {
    const m = {};
    for (const et of (workspace.schema?.edge_types || [])) m[et.name] = et;
    return m;
  }, [workspace.schema]);
  const actionToEdgeType = workspace.actionTypeToEdgeType || {};
  function colorForAction(action) {
    const name = actionToEdgeType[action];
    return name ? (edgeMetaByName[name]?.color || null) : null;
  }

  // Notes — keyed by record_id + eid if available, fallback to navIdx
  const noteKey = currentEv?.source?.record_id
    ? `event:${currentEv.source.eid}:${currentEv.source.record_id}`
    : `event:edge:${navIdx}`;
  const existingNote = annotations.find(a => a.annotation_type === 'note' && a.node_id === noteKey);
  const [noteText, setNoteText] = useState(existingNote?.text || '');
  const [noteSaved, setNoteSaved] = useState(false);
  useEffect(() => {
    const note = annotations.find(a => a.annotation_type === 'note' && a.node_id === noteKey);
    setNoteText(note?.text || '');
    setNoteSaved(false);
  }, [noteKey, annotations]);
  const saveNote = useCallback(async () => {
    if (onSaveNote) {
      await onSaveNote(noteKey, noteText, existingNote?.id);
      setNoteSaved(true);
      setTimeout(() => setNoteSaved(false), 1500);
    }
  }, [noteKey, noteText, existingNote, onSaveNote]);

  if (!currentEv) return null;

  const { action_type, ts, fields = {}, source = {} } = currentEv;
  const actionColor = colorForAction(action_type) || '#8b949e';
  const edgeColor   = edgeContext?.edgeColor || '#8b949e';

  return (
    <div className="fi" style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      {/* ── Sticky header ──────────────────────────────────────────── */}
      <div style={{
        flexShrink: 0, padding: '16px 16px 12px 16px',
        background: 'var(--bgS)', borderBottom: '1px solid var(--bd)',
      }}>
        {/* Top row: title + nav + close */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
          <div className="sh" style={{ marginBottom: 0 }}>Event Detail</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            {hasSibs && (
              <>
                <button
                  className="btn"
                  onClick={() => setNavIdx(i => Math.max(0, i - 1))}
                  disabled={navIdx <= 0}
                  style={{ fontSize: 11, padding: '1px 7px', opacity: navIdx <= 0 ? 0.3 : 1 }}
                >‹</button>
                <span style={{ fontSize: 9, color: 'var(--txD)', minWidth: 40, textAlign: 'center' }}>
                  {navIdx + 1} / {events.length}
                </span>
                <button
                  className="btn"
                  onClick={() => setNavIdx(i => Math.min(events.length - 1, i + 1))}
                  disabled={navIdx >= events.length - 1}
                  style={{ fontSize: 11, padding: '1px 7px', opacity: navIdx >= events.length - 1 ? 0.3 : 1 }}
                >›</button>
              </>
            )}
            <button className="btn" onClick={onBack}>✕</button>
          </div>
        </div>

        {/* Action name — large, colored */}
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 6, color: actionColor }}>
          {actionLabel(action_type)}
        </div>

        {/* EID · computer · timestamp — single compact row */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
          {source.eid && (
            <span style={{
              fontSize: 9, padding: '1px 6px', borderRadius: 5, fontWeight: 600,
              background: 'rgba(139,148,158,.15)', color: '#8b949e',
              border: '1px solid rgba(139,148,158,.25)',
            }}>EID {source.eid}</span>
          )}
          {source.computer && (
            <span style={{ fontSize: 9, color: 'var(--txD)', fontFamily: 'var(--fn)' }}>
              {source.computer}
            </span>
          )}
          <span style={{ fontSize: 9, color: 'var(--txD)', fontFamily: 'var(--fn)' }}>
            {formatTs(ts)}
          </span>
        </div>

        {/* Edge context: src → dst */}
        {edgeContext && (
          <div style={{
            padding: '6px 8px',
            background: 'var(--bgC)', border: '1px solid var(--bd)', borderRadius: 4,
            display: 'flex', alignItems: 'center', gap: 6, fontSize: 10,
          }}>
            <span style={{
              color: 'var(--txM)', flex: 1, overflow: 'hidden',
              textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }} title={edgeContext.srcLabel}>{edgeContext.srcLabel}</span>
            <span style={{ color: edgeColor, fontSize: 11, flexShrink: 0 }}>→</span>
            <span style={{
              color: 'var(--txM)', flex: 1, overflow: 'hidden',
              textOverflow: 'ellipsis', whiteSpace: 'nowrap', textAlign: 'right',
            }} title={edgeContext.dstLabel}>{edgeContext.dstLabel}</span>
          </div>
        )}
      </div>

      {/* ── Scrollable content ──────────────────────────────────────── */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '14px 16px 16px 16px' }}>

        {/* Per-action content */}
        {action_type === 'process_create'  && <ProcessCreateContent  fields={fields} />}
        {action_type === 'network_connect' && <NetworkConnectContent fields={fields} />}
        {action_type === 'file_create'     && <FileCreateContent     fields={fields} />}
        {action_type === 'registry_set'    && <RegistrySetContent    fields={fields} />}
        {!['process_create', 'network_connect', 'file_create', 'registry_set'].includes(action_type) && (
          <GenericContent fields={fields} />
        )}

        {/* Provenance */}
        {(source.eid || source.record_id || source.provider) && (
          <Collapse title="Provenance">
            {source.eid       && <Row l="Event ID"    v={String(source.eid)} />}
            {source.record_id && <Row l="Record ID"   v={String(source.record_id)} />}
            {source.computer  && <Row l="Computer"    v={source.computer} />}
            {source.provider  && <Row l="Provider"    v={source.provider} />}
          </Collapse>
        )}

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
    </div>
  );
}
