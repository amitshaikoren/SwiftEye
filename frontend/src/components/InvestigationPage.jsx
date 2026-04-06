/**
 * InvestigationPage — Researcher notebook for documenting findings.
 *
 * Split-pane: markdown editor (left) + live preview (right).
 * Supports screenshots via paste (Ctrl+V) or drag-and-drop.
 * Images are uploaded to the backend and embedded via ![alt](img_id).
 * Export to PDF via backend endpoint.
 */
import React, { useState, useEffect, useRef, useCallback } from 'react';
import { fetchInvestigation, saveInvestigation, uploadInvestigationImage } from '../api';

// ── Lightweight markdown renderer ──────────────────────────────────────────

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

  // Close unclosed code block
  if (inCode && codeLines.length) {
    html += `<pre style="background:var(--bgH);border:1px solid var(--bd);border-radius:6px;padding:10px 14px;font-size:11px;font-family:var(--fn);overflow-x:auto;margin:8px 0;color:var(--tx)">${esc(codeLines.join('\n'))}</pre>`;
  }

  return html;
}

function esc(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function inline(text) {
  let s = esc(text);
  s = s.replace(/\*\*(.+?)\*\*/g, '<strong style="color:var(--tx)">$1</strong>');
  s = s.replace(/__(.+?)__/g, '<strong style="color:var(--tx)">$1</strong>');
  s = s.replace(/\*(.+?)\*/g, '<em>$1</em>');
  s = s.replace(/_(.+?)_/g, '<em>$1</em>');
  s = s.replace(/`(.+?)`/g, '<code style="background:var(--bgH);padding:1px 5px;border-radius:3px;font-size:11px;font-family:var(--fn)">$1</code>');
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

export default function InvestigationPage() {
  const [markdown, setMarkdown] = useState('');
  const [images, setImages] = useState({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [view, setView] = useState('split'); // 'edit' | 'preview' | 'split'
  const editorRef = useRef(null);

  // Load on mount
  useEffect(() => {
    setLoading(true);
    fetchInvestigation().then(d => {
      setMarkdown(d.markdown || '');
      setImages(d.images || {});
    }).catch(() => {}).finally(() => setLoading(false));
  }, []);

  // Auto-save
  useAutoSave(markdown);

  // Handle image paste / drop
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
          // Move cursor after the inserted tag
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

  function handleDrop(e) {
    e.preventDefault();
    const file = e.dataTransfer?.files?.[0];
    if (file && file.type.startsWith('image/')) handleImage(file);
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

  // Template insertion helpers
  function insertTemplate(template) {
    const ta = editorRef.current;
    if (!ta) return;
    const pos = ta.selectionStart;
    const before = markdown.slice(0, pos);
    const after = markdown.slice(pos);
    setMarkdown(before + template + after);
    setTimeout(() => { ta.selectionStart = ta.selectionEnd = pos + template.length; ta.focus(); }, 0);
  }

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
      <div style={{ padding: '10px 24px', borderBottom: '1px solid var(--bd)', display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0, background: 'var(--bgP)' }}>
        <div style={{ fontSize: 16, fontWeight: 700, fontFamily: 'var(--fd)', color: 'var(--tx)', marginRight: 8 }}>Investigation</div>

        {/* View toggles */}
        {['edit', 'split', 'preview'].map(v => (
          <button key={v} className={'btn' + (view === v ? ' on' : '')}
            onClick={() => setView(v)} style={{ fontSize: 9, padding: '2px 8px', textTransform: 'capitalize' }}>{v}</button>
        ))}

        <div style={{ flex: 1 }} />

        {/* Insert buttons */}
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

        <span style={{ width: 1, height: 16, background: 'var(--bd)', margin: '0 4px' }} />

        <button className="btn" onClick={handleManualSave} disabled={saving}
          style={{ fontSize: 9, padding: '2px 10px' }}>{saving ? 'Saving…' : 'Save'}</button>

        <button className="btn" onClick={handleExport} disabled={exporting || !markdown.trim()}
          style={{ fontSize: 9, padding: '2px 10px', background: 'rgba(88,166,255,.1)', borderColor: 'var(--ac)', color: 'var(--ac)' }}>
          {exporting ? 'Exporting…' : '⬇ Export PDF'}
        </button>
      </div>

      {/* Editor + Preview */}
      <div style={{ flex: 1, display: 'flex', minHeight: 0, overflow: 'hidden' }}>
        {/* Editor pane */}
        {showEditor && (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, borderRight: showPreview ? '1px solid var(--bd)' : 'none' }}>
            <div style={{ padding: '4px 12px', fontSize: 9, color: 'var(--txD)', borderBottom: '1px solid var(--bd)', background: 'var(--bgP)', flexShrink: 0 }}>
              MARKDOWN · Ctrl+V to paste screenshots · auto-saves
            </div>
            <textarea
              ref={editorRef}
              value={markdown}
              onChange={e => setMarkdown(e.target.value)}
              onPaste={handlePaste}
              onDrop={handleDrop}
              onDragOver={e => e.preventDefault()}
              placeholder={"# Investigation Notes\n\nStart documenting your findings here...\n\n## Key Observations\n\n- Paste screenshots with Ctrl+V\n- Use **bold** and *italic* for emphasis\n- Code blocks with triple backticks\n\n## Conclusion\n\n..."}
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
              PREVIEW
            </div>
            <div style={{ flex: 1, overflow: 'auto', padding: '16px 24px' }}
              dangerouslySetInnerHTML={{ __html: renderMarkdown(markdown, images) || '<div style="color:var(--txD);font-size:12px;font-style:italic">Start typing to see the preview…</div>' }}
            />
          </div>
        )}
      </div>
    </div>
  );
}
