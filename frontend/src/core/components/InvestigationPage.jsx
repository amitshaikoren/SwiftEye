/**
 * InvestigationPage — Researcher notebook + Timeline Graph (v0.21.0).
 *
 * Two tabs:
 *   - Documentation: markdown editor (split / edit / preview) — UNCHANGED
 *     behavior except that dragging an Event card from the right-side panel
 *     into the editor inserts an `<event-ref/>` token, and the preview
 *     renders those tokens as colored, clickable chips.
 *   - Timeline Graph: SVG canvas of placed events with manual + suggested
 *     edges, ruler-by-time toggle, and edge detail panel. Implemented in
 *     `TimelineGraph.jsx`.
 *
 * The Flagged Events panel (`EventsPanel`) is always visible on the right
 * in both tabs — researchers drag cards from it into the editor or onto
 * the canvas.
 *
 * Props (passed from App.jsx via useCapture):
 *   events, suggestedEdges, timelineEdges, addTimelineEdge, ...
 *   onSelectEntity(entity_type, entity_id) — chip click → graph
 *   removeEvent, updateEvent, openFlagModal, etc.
 */
import React, { useState, useEffect, useRef, useCallback } from 'react';
import { fetchInvestigation, saveInvestigation, uploadInvestigationImage } from '../api';
import EventsPanel from './EventsPanel';
import TimelineGraph from './TimelineGraph';
import { SEVERITY_COLOR } from '../hooks/useEvents';

// ── Markdown rendering ─────────────────────────────────────────────────────
//
// Lightweight renderer (carried over from the original page). New in v0.21.0:
// `<event-ref id="..." title="..." severity="..."/>` tokens are inlined as
// colored chips. Render is HTML-string based; click handling is done by a
// delegated listener on the preview container (looks for [data-event-ref]).

function renderMarkdown(md, images) {
  if (!md) return '';
  const lines = md.split('\n');
  let html = '';
  let inCode = false;
  let codeLines = [];

  for (const line of lines) {
    if (line.trim().startsWith('```')) {
      if (inCode) {
        html += `<pre style="background:var(--bgH);border:1px solid var(--bd);border-radius:6px;padding:10px 14px;font-size:11px;font-family:var(--fn);overflow-x:auto;margin:8px 0;color:var(--tx)">${esc(codeLines.join('\n'))}</pre>`;
        codeLines = [];
        inCode = false;
      } else {
        inCode = true;
      }
      continue;
    }
    if (inCode) { codeLines.push(line); continue; }

    const s = line.trim();
    if (!s) { html += '<div style="height:8px"></div>'; continue; }
    if (s === '---' || s === '***' || s === '___') { html += '<hr style="border:none;border-top:1px solid var(--bd);margin:12px 0">'; continue; }
    if (s.startsWith('### ')) { html += `<div style="font-size:13px;font-weight:700;color:var(--tx);margin:14px 0 6px">${inline(s.slice(4))}</div>`; continue; }
    if (s.startsWith('## '))  { html += `<div style="font-size:15px;font-weight:700;color:var(--tx);margin:16px 0 8px">${inline(s.slice(3))}</div>`; continue; }
    if (s.startsWith('# '))   { html += `<div style="font-size:18px;font-weight:700;color:var(--tx);margin:20px 0 10px">${inline(s.slice(2))}</div>`; continue; }

    // Image
    const imgMatch = s.match(/^!\[([^\]]*)\]\(([^)]+)\)$/);
    if (imgMatch) {
      const [, alt, src] = imgMatch;
      const url = (images && images[src]) || src;
      html += `<div style="margin:10px 0;text-align:center"><img src="${esc(url)}" alt="${esc(alt)}" style="max-width:100%;border-radius:8px;border:1px solid var(--bd)"><div style="font-size:9px;color:var(--txD);margin-top:4px">${esc(alt)}</div></div>`;
      continue;
    }

    // Bullet
    if (s.startsWith('- ') || s.startsWith('* ')) {
      html += `<div style="padding:2px 0 2px 16px;font-size:12px;color:var(--txM);line-height:1.7">&bull; ${inline(s.slice(2))}</div>`;
      continue;
    }

    // Numbered list
    const numMatch = s.match(/^(\d+)\.\s/);
    if (numMatch) {
      html += `<div style="padding:2px 0 2px 16px;font-size:12px;color:var(--txM);line-height:1.7">${numMatch[1]}. ${inline(s.slice(numMatch[0].length))}</div>`;
      continue;
    }

    // Blockquote
    if (s.startsWith('> ')) {
      html += `<div style="border-left:3px solid var(--ac);padding:4px 12px;margin:6px 0;color:var(--txD);font-size:12px;font-style:italic">${inline(s.slice(2))}</div>`;
      continue;
    }

    html += `<div style="font-size:12px;color:var(--txM);line-height:1.7;margin:2px 0">${inline(s)}</div>`;
  }

  if (inCode && codeLines.length) {
    html += `<pre style="background:var(--bgH);border:1px solid var(--bd);border-radius:6px;padding:10px 14px;font-size:11px;font-family:var(--fn);overflow-x:auto;margin:8px 0;color:var(--tx)">${esc(codeLines.join('\n'))}</pre>`;
  }

  return html;
}

function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// Render a single event-ref token as a colored chip span. Quotes inside
// the attribute values are HTML-escaped to prevent attribute breaking.
function renderEventChip(id, title, severity) {
  const color = SEVERITY_COLOR[severity] || '#8b949e';
  const safeTitle = esc(title || 'Event');
  const safeId = esc(id || '');
  return `<span data-event-ref="${safeId}" style="display:inline-flex;align-items:center;gap:4px;background:rgba(255,255,255,.04);border:1px solid ${color};border-radius:10px;padding:0 8px 0 6px;color:${color};font-size:11px;font-family:var(--fn);cursor:pointer;vertical-align:baseline;line-height:1.7;margin:0 2px"><span style="width:6px;height:6px;border-radius:50%;background:${color};display:inline-block"></span>${safeTitle}</span>`;
}

function inline(text) {
  // Process event-ref tokens BEFORE escaping the text. We pull them out,
  // render them to HTML chips, and replace each with a placeholder that
  // survives escaping, then swap back at the end.
  const placeholders = [];
  const stripped = String(text).replace(
    /<event-ref\s+([^/>]*)\/?>/gi,
    (_, attrs) => {
      const idMatch = attrs.match(/id="([^"]*)"/i);
      const titleMatch = attrs.match(/title="([^"]*)"/i);
      const sevMatch = attrs.match(/severity="([^"]*)"/i);
      const html = renderEventChip(
        idMatch ? idMatch[1] : '',
        titleMatch ? titleMatch[1] : 'Event',
        sevMatch ? sevMatch[1] : null,
      );
      placeholders.push(html);
      return `\u0000EVREF${placeholders.length - 1}\u0000`;
    }
  );

  let s = esc(stripped);
  s = s.replace(/\*\*(.+?)\*\*/g, '<strong style="color:var(--tx)">$1</strong>');
  s = s.replace(/__(.+?)__/g, '<strong style="color:var(--tx)">$1</strong>');
  s = s.replace(/\*(.+?)\*/g, '<em>$1</em>');
  s = s.replace(/_(.+?)_/g, '<em>$1</em>');
  s = s.replace(/`(.+?)`/g, '<code style="background:var(--bgH);padding:1px 5px;border-radius:3px;font-size:11px;font-family:var(--fn)">$1</code>');
  // Swap event-ref placeholders back. The escape pass turned our \u0000
  // sentinels into themselves (NUL is preserved by .replace), so we can
  // match the same pattern.
  s = s.replace(/\u0000EVREF(\d+)\u0000/g, (_, i) => placeholders[Number(i)] || '');
  return s;
}

// ── Auto-save hook ─────────────────────────────────────────────────────────

function useAutoSave(markdown, delay = 1500) {
  const timer = useRef(null);
  const lastSaved = useRef(markdown);

  useEffect(() => {
    if (markdown === lastSaved.current) return;
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      saveInvestigation(markdown).then(() => { lastSaved.current = markdown; }).catch(() => {});
    }, delay);
    return () => { if (timer.current) clearTimeout(timer.current); };
  }, [markdown, delay]);
}

// ── Main component ─────────────────────────────────────────────────────────

export default function InvestigationPage({
  // Events plumbing — passed from useCapture via App.jsx
  events = [],
  timelineEdges = [],
  suggestedEdges = [],
  addTimelineEdge,
  updateTimelineEdge,
  removeTimelineEdge,
  acceptSuggestion,
  rejectSuggestion,
  rulerOn,
  setRulerOn,
  placeEvent,
  unplaceEvent,
  removeEvent,
  updateEvent,
  onSelectEntity, // (entity_type, entity_id) — switch to graph + highlight
  tab: tabProp,
  setTab: setTabProp,
}) {
  // Tab state may be lifted into App.jsx (so the back-to-timeline breadcrumb
  // can restore the right tab on return). Fall back to local state if not.
  const [localTab, setLocalTab] = useState('documentation');
  const tab = tabProp ?? localTab;
  const setTab = setTabProp ?? setLocalTab;
  const [markdown, setMarkdown] = useState('');
  const [images, setImages] = useState({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [view, setView] = useState('split'); // edit | preview | split
  const editorRef = useRef(null);

  useEffect(() => {
    setLoading(true);
    fetchInvestigation().then(d => {
      setMarkdown(d.markdown || '');
      setImages(d.images || {});
    }).catch(() => {}).finally(() => setLoading(false));
  }, []);

  useAutoSave(markdown);

  // ── Image paste / drop ───────────────────────────────────────────────────

  const handleImage = useCallback(async (file) => {
    if (!file || !file.type.startsWith('image/')) return;
    try {
      const result = await uploadInvestigationImage(file);
      const tag = `![Screenshot](${result.id})`;
      setImages(prev => ({ ...prev, [result.id]: result.url }));
      setMarkdown(prev => {
        const ta = editorRef.current;
        if (ta) {
          const pos = ta.selectionStart;
          const before = prev.slice(0, pos);
          const after = prev.slice(pos);
          const next = before + '\n' + tag + '\n' + after;
          setTimeout(() => { ta.selectionStart = ta.selectionEnd = pos + tag.length + 2; ta.focus(); }, 0);
          return next;
        }
        return prev + '\n' + tag + '\n';
      });
    } catch (e) {
      console.error('Image upload failed:', e);
    }
  }, []);

  function handlePaste(e) {
    const items = e.clipboardData?.items;
    if (!items) return;
    for (const item of items) {
      if (item.type.startsWith('image/')) {
        e.preventDefault();
        handleImage(item.getAsFile());
        return;
      }
    }
  }

  // ── Drop handler — image OR event card ───────────────────────────────────

  function handleDrop(e) {
    e.preventDefault();
    // Event card dropped: insert ref-chip token at cursor
    const eventId = e.dataTransfer?.getData('application/x-swifteye-event');
    if (eventId) {
      const ev = events.find(x => x.id === eventId);
      if (!ev) return;
      const sevAttr = ev.severity ? ` severity="${ev.severity}"` : '';
      const safeTitle = (ev.title || '').replace(/"/g, "'");
      const token = `<event-ref id="${ev.id}" title="${safeTitle}"${sevAttr}/>`;
      insertAtCursor(token);
      return;
    }
    // Otherwise: image drop
    const file = e.dataTransfer?.files?.[0];
    if (file && file.type.startsWith('image/')) handleImage(file);
  }

  function handleDragOver(e) {
    if (e.dataTransfer?.types?.includes('application/x-swifteye-event') ||
        e.dataTransfer?.types?.includes('Files')) {
      e.preventDefault();
      e.dataTransfer.dropEffect = 'copy';
    }
  }

  function insertAtCursor(text) {
    setMarkdown(prev => {
      const ta = editorRef.current;
      if (ta) {
        const pos = ta.selectionStart ?? prev.length;
        const before = prev.slice(0, pos);
        const after = prev.slice(pos);
        setTimeout(() => { ta.selectionStart = ta.selectionEnd = pos + text.length; ta.focus(); }, 0);
        return before + text + after;
      }
      return prev + text;
    });
  }

  function handleFileUpload(e) {
    const file = e.target.files?.[0];
    if (file) handleImage(file);
  }

  async function handleExport() {
    setExporting(true);
    try {
      await saveInvestigation(markdown);
      const res = await fetch('/api/investigation/export', { method: 'POST' });
      if (!res.ok) throw new Error(`Export failed: ${res.status}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'investigation.pdf';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error('Export failed:', e);
    } finally {
      setExporting(false);
    }
  }

  async function handleManualSave() {
    setSaving(true);
    try { await saveInvestigation(markdown); } catch {} finally { setSaving(false); }
  }

  function insertTemplate(template) {
    insertAtCursor(template);
  }

  // ── Click-on-chip in preview → highlight entity in main graph ────────────

  function handlePreviewClick(e) {
    let el = e.target;
    while (el && el !== e.currentTarget) {
      const refId = el.getAttribute && el.getAttribute('data-event-ref');
      if (refId) {
        const ev = events.find(x => x.id === refId);
        if (ev && onSelectEntity) {
          if (ev.entity_type === 'node')    onSelectEntity('node', ev.node_id);
          if (ev.entity_type === 'edge')    onSelectEntity('edge', ev.edge_id);
          if (ev.entity_type === 'session') onSelectEntity('session', ev.session_id);
        }
        return;
      }
      el = el.parentElement;
    }
  }

  // ── Loading screen ───────────────────────────────────────────────────────

  if (loading) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'var(--txM)', fontSize: 11 }}>
          <div style={{ width: 16, height: 16, border: '2px solid var(--bd)', borderTopColor: 'var(--ac)', borderRadius: '50%', animation: 'spin 0.7s linear infinite' }} />
          Loading investigation…
        </div>
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      </div>
    );
  }

  const showEditor = view === 'edit' || view === 'split';
  const showPreview = view === 'preview' || view === 'split';

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, background: 'var(--bg)' }}>
      {/* Toolbar */}
      <div style={{
        padding: '8px 16px', borderBottom: '1px solid var(--bd)',
        display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0,
        background: 'var(--bgP)', flexWrap: 'wrap',
      }}>
        <div style={{ fontSize: 16, fontWeight: 700, fontFamily: 'var(--fd)', color: 'var(--tx)', marginRight: 8 }}>Investigation</div>

        {/* Tab bar */}
        <div style={{ display: 'flex', gap: 2, marginRight: 8 }}>
          <button className={'btn' + (tab === 'documentation' ? ' on' : '')}
            onClick={() => setTab('documentation')} style={{ fontSize: 10, padding: '3px 12px' }}>Documentation</button>
          <button className={'btn' + (tab === 'timeline' ? ' on' : '')}
            onClick={() => setTab('timeline')} style={{ fontSize: 10, padding: '3px 12px' }}>Timeline Graph</button>
        </div>

        {/* Documentation tab tools */}
        {tab === 'documentation' && (
          <>
            <div style={{ width: 1, height: 18, background: 'var(--bd)' }} />
            {['edit', 'split', 'preview'].map(v => (
              <button key={v} className={'btn' + (view === v ? ' on' : '')}
                onClick={() => setView(v)} style={{ fontSize: 9, padding: '2px 8px', textTransform: 'capitalize' }}>{v}</button>
            ))}
            <div style={{ width: 1, height: 18, background: 'var(--bd)' }} />
            <button className="btn" onClick={() => insertTemplate('# ')} title="Heading" style={{ fontSize: 10, padding: '2px 6px', fontWeight: 700 }}>H</button>
            <button className="btn" onClick={() => insertTemplate('**bold**')} title="Bold" style={{ fontSize: 10, padding: '2px 6px', fontWeight: 700 }}>B</button>
            <button className="btn" onClick={() => insertTemplate('*italic*')} title="Italic" style={{ fontSize: 10, padding: '2px 6px', fontStyle: 'italic' }}>I</button>
            <button className="btn" onClick={() => insertTemplate('```\ncode\n```')} title="Code block" style={{ fontSize: 9, padding: '2px 6px', fontFamily: 'var(--fn)' }}>&lt;/&gt;</button>
            <button className="btn" onClick={() => insertTemplate('- ')} title="Bullet list" style={{ fontSize: 10, padding: '2px 6px' }}>•</button>
            <button className="btn" onClick={() => insertTemplate('---\n')} title="Horizontal rule" style={{ fontSize: 10, padding: '2px 6px' }}>—</button>
            <label className="btn" style={{ fontSize: 9, padding: '2px 8px', cursor: 'pointer' }} title="Upload image">
              📷
              <input type="file" accept="image/*" onChange={handleFileUpload} style={{ display: 'none' }} />
            </label>
          </>
        )}

        <div style={{ flex: 1 }} />

        {/* Save / export — only on Documentation tab (PDF export is markdown-only) */}
        {tab === 'documentation' && (
          <>
            <button className="btn" onClick={handleManualSave} disabled={saving}
              style={{ fontSize: 9, padding: '2px 10px' }}>{saving ? 'Saving…' : 'Save'}</button>
            <button className="btn" onClick={handleExport} disabled={exporting || !markdown.trim()}
              style={{ fontSize: 9, padding: '2px 10px', background: 'rgba(88,166,255,.1)', borderColor: 'var(--ac)', color: 'var(--ac)' }}>
              {exporting ? 'Exporting…' : '⬇ Export PDF'}
            </button>
          </>
        )}
      </div>

      {/* Main row: tab content + EventsPanel */}
      <div style={{ flex: 1, display: 'flex', minHeight: 0, overflow: 'hidden' }}>

        {/* Tab content (left/center) */}
        <div style={{ flex: 1, display: 'flex', minWidth: 0, minHeight: 0 }}>
          {tab === 'documentation' ? (
            <div style={{ flex: 1, display: 'flex', minHeight: 0, overflow: 'hidden' }}>
              {/* Editor pane */}
              {showEditor && (
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, borderRight: showPreview ? '1px solid var(--bd)' : 'none' }}>
                  <div style={{ padding: '4px 12px', fontSize: 9, color: 'var(--txD)', borderBottom: '1px solid var(--bd)', background: 'var(--bgP)', flexShrink: 0 }}>
                    MARKDOWN · Ctrl+V to paste screenshots · drag event cards in · auto-saves
                  </div>
                  <textarea
                    ref={editorRef}
                    value={markdown}
                    onChange={e => setMarkdown(e.target.value)}
                    onPaste={handlePaste}
                    onDrop={handleDrop}
                    onDragOver={handleDragOver}
                    placeholder={"# Investigation Notes\n\nStart documenting your findings here...\n\n## Key Observations\n\n- Drag flagged events from the right panel into your notes\n- Paste screenshots with Ctrl+V\n- Use **bold** and *italic* for emphasis\n\n## Conclusion\n\n..."}
                    style={{
                      flex: 1, resize: 'none', border: 'none', outline: 'none',
                      background: 'var(--bg)', color: 'var(--tx)',
                      fontFamily: 'var(--fn)', fontSize: 12, lineHeight: 1.7,
                      padding: '16px 20px', overflow: 'auto',
                    }}
                    spellCheck={false}
                  />
                </div>
              )}

              {/* Preview pane */}
              {showPreview && (
                <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
                  <div style={{ padding: '4px 12px', fontSize: 9, color: 'var(--txD)', borderBottom: '1px solid var(--bd)', background: 'var(--bgP)', flexShrink: 0 }}>
                    PREVIEW · click an event chip to highlight in graph
                  </div>
                  <div
                    onClick={handlePreviewClick}
                    style={{ flex: 1, overflow: 'auto', padding: '16px 24px' }}
                    dangerouslySetInnerHTML={{ __html: renderMarkdown(markdown, images) || '<div style="color:var(--txD);font-size:12px;font-style:italic">Start typing to see the preview…</div>' }}
                  />
                </div>
              )}
            </div>
          ) : (
            // Timeline Graph tab
            <TimelineGraph
              events={events}
              timelineEdges={timelineEdges}
              suggestedEdges={suggestedEdges}
              addTimelineEdge={addTimelineEdge}
              updateTimelineEdge={updateTimelineEdge}
              removeTimelineEdge={removeTimelineEdge}
              updateEvent={updateEvent}
              acceptSuggestion={acceptSuggestion}
              rejectSuggestion={rejectSuggestion}
              rulerOn={rulerOn}
              setRulerOn={setRulerOn}
              placeEvent={placeEvent}
              unplaceEvent={unplaceEvent}
              onSelectEntity={onSelectEntity}
            />
          )}
        </div>

        {/* Right-side flagged events panel — always visible */}
        <EventsPanel
          events={events}
          onEventClick={(ev) => {
            if (ev.entity_type === 'node')    onSelectEntity?.('node', ev.node_id);
            if (ev.entity_type === 'edge')    onSelectEntity?.('edge', ev.edge_id);
            if (ev.entity_type === 'session') onSelectEntity?.('session', ev.session_id);
          }}
          onEditEvent={(ev) => {/* TODO Phase 2: edit modal */}}
          onRemoveEvent={(ev) => removeEvent?.(ev.id)}
        />
      </div>
    </div>
  );
}
