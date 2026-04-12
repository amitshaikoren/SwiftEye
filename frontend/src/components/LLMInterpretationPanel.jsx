/**
 * LLMInterpretationPanel — the researcher Q&A surface over the loaded capture.
 *
 * Features:
 *  - Scope selector: Full capture / Current view / Selected entity
 *  - Question input with send/cancel
 *  - Streaming transcript with markdown rendering
 *  - "Explain this" quick action when an entity is selected
 *  - Context-changed badge when scope snapshot changes
 *  - Error state and loading indicator
 *  - Link to LLM settings
 */

import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useLlmChat } from '../hooks/useLlmChat';

// ── Minimal markdown renderer (no dependencies) ───────────────────────────────
// Handles: ## headings, **bold**, `code`, - bullet lists, blank lines.
function renderMarkdown(md) {
  if (!md) return null;
  const lines = md.split('\n');
  const elements = [];
  let key = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Heading
    const hm = line.match(/^(#{1,3})\s+(.+)/);
    if (hm) {
      const level = hm[1].length;
      const sizes = [16, 14, 12];
      elements.push(
        <div key={key++} style={{ fontSize: sizes[level - 1] || 12, fontWeight: 600, color: 'var(--tx)', margin: '10px 0 4px' }}>
          {inlineFormat(hm[2])}
        </div>
      );
      continue;
    }

    // Bullet
    const bm = line.match(/^[-*]\s+(.+)/);
    if (bm) {
      elements.push(
        <div key={key++} style={{ display: 'flex', gap: 6, fontSize: 11, color: 'var(--txM)', marginBottom: 3 }}>
          <span style={{ color: 'var(--txD)', flexShrink: 0 }}>•</span>
          <span>{inlineFormat(bm[1])}</span>
        </div>
      );
      continue;
    }

    // Empty line
    if (!line.trim()) {
      elements.push(<div key={key++} style={{ height: 6 }} />);
      continue;
    }

    // Regular paragraph
    elements.push(
      <div key={key++} style={{ fontSize: 11, color: 'var(--txM)', lineHeight: 1.65, marginBottom: 2 }}>
        {inlineFormat(line)}
      </div>
    );
  }

  return elements;
}

function inlineFormat(text) {
  // Split on **bold** and `code`
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={i} style={{ color: 'var(--tx)' }}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return (
        <code key={i} style={{
          fontFamily: 'var(--fn)', fontSize: 10,
          background: 'var(--bgH)', padding: '1px 5px', borderRadius: 3,
          color: 'var(--ac)',
        }}>{part.slice(1, -1)}</code>
      );
    }
    return part;
  });
}

// ── Scope selector ────────────────────────────────────────────────────────────

const SCOPE_MODES = [
  { id: 'full_capture', label: 'Full capture' },
  { id: 'current_view', label: 'Current view' },
  { id: 'selected_entity', label: 'Selected entity' },
];

// ── Tag badge colours ─────────────────────────────────────────────────────────
const TAG_COLORS = {
  alert_evidence:    { bg: 'rgba(255,80,80,.12)',  fg: '#ff8080' },
  attribution_risk:  { bg: 'rgba(255,160,0,.12)', fg: '#ffb040' },
  entity_node:       { bg: 'rgba(88,166,255,.12)', fg: 'var(--ac)' },
  entity_edge:       { bg: 'rgba(88,166,255,.12)', fg: 'var(--ac)' },
  entity_session:    { bg: 'rgba(88,166,255,.12)', fg: 'var(--ac)' },
  dns:               { bg: 'rgba(100,220,130,.1)', fg: '#64dc82' },
  tls:               { bg: 'rgba(100,220,130,.1)', fg: '#64dc82' },
  http:              { bg: 'rgba(100,220,130,.1)', fg: '#64dc82' },
  credentials:       { bg: 'rgba(255,80,80,.12)',  fg: '#ff8080' },
  mixed_question:    { bg: 'rgba(188,140,255,.1)', fg: 'var(--acP)' },
  capture_adjacent_background_question: { bg: 'rgba(150,150,150,.1)', fg: 'var(--txD)' },
  unrelated_question: { bg: 'rgba(150,150,150,.1)', fg: 'var(--txD)' },
  broad_overview:    { bg: 'rgba(88,166,255,.08)', fg: 'var(--ac)' },
};

function TagBadge({ tag }) {
  const c = TAG_COLORS[tag] || { bg: 'rgba(150,150,150,.1)', fg: 'var(--txD)' };
  const label = tag.replace(/_/g, ' ');
  return (
    <span style={{
      fontSize: 9, padding: '1px 6px', borderRadius: 8,
      background: c.bg, color: c.fg,
      border: `1px solid ${c.fg}40`,
      letterSpacing: '.04em', whiteSpace: 'nowrap',
    }}>{label}</span>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function LLMInterpretationPanel({
  // Viewer state (passed from App → AnalysisPage → here)
  filters,          // { timeStart, timeEnd, protocols, search, includeIPv6, subnetGrouping, subnetPrefix, mergeByMac }
  selection,        // { nodeIds, edgeId, sessionId, alertId }
  // Settings
  settings,
  onOpenSettings,
}) {
  const { turns, streaming, error, send, cancel, clear } = useLlmChat();

  const [scopeMode, setScopeMode] = useState('full_capture');
  const [input, setInput] = useState('');
  const transcriptRef = useRef(null);

  const hasSelection = !!(
    (selection?.nodeIds?.length) ||
    selection?.edgeId ||
    selection?.sessionId ||
    selection?.alertId
  );

  // Auto-scroll transcript
  useEffect(() => {
    if (transcriptRef.current) {
      transcriptRef.current.scrollTop = transcriptRef.current.scrollHeight;
    }
  }, [turns]);

  // If selected entity is de-selected while in selected_entity mode, fall back
  useEffect(() => {
    if (scopeMode === 'selected_entity' && !hasSelection) {
      setScopeMode('current_view');
    }
  }, [hasSelection, scopeMode]);

  const buildRequest = useCallback(() => {
    const vs = filters || {};
    const sel = selection || {};

    return {
      scope: {
        mode: scopeMode,
        entity_type: _inferEntityType(sel),
        entity_id: _inferEntityId(sel),
      },
      viewer_state: {
        time_start: vs.timeStart ?? null,
        time_end:   vs.timeEnd   ?? null,
        protocols:  vs.protocols ?? null,
        search:     vs.search    ?? '',
        include_ipv6:     vs.includeIPv6 !== false,
        subnet_grouping:  vs.subnetGrouping || false,
        subnet_prefix:    vs.subnetPrefix   || 24,
        merge_by_mac:     vs.mergeByMac     || false,
        cluster_algorithm: null,
        cluster_resolution: 1.0,
      },
      selection: {
        node_ids:   sel.nodeIds   || [],
        edge_id:    sel.edgeId    || null,
        session_id: sel.sessionId || null,
        alert_id:   sel.alertId   || null,
      },
      provider: {
        kind:        settings?.llmProvider || 'ollama',
        model:       settings?.llmModel    || 'qwen2.5:14b-instruct',
        base_url:    settings?.llmBaseUrl  || null,
        api_key:     settings?.llmApiKey   || null,
        temperature: settings?.llmTemperature ?? 0.2,
        max_tokens:  settings?.llmMaxTokens   ?? 1400,
      },
      options: {
        intent: 'qa',
        allow_context_expansion: true,
        debug_return_context: false,
      },
    };
  }, [scopeMode, filters, selection, settings]);

  const handleSend = useCallback(() => {
    const q = input.trim();
    if (!q || streaming) return;
    setInput('');
    send(q, buildRequest());
  }, [input, streaming, send, buildRequest]);

  const handleExplain = useCallback(() => {
    if (streaming) return;
    let q = 'What is happening in this current view?';
    if (scopeMode === 'selected_entity' && hasSelection) {
      const sel = selection || {};
      if (sel.alertId)   q = 'Why did this alert fire?';
      else if (sel.edgeId)   q = 'What do we know about this edge?';
      else if (sel.sessionId) q = 'What do we know about this session?';
      else if (sel.nodeIds?.length) q = `What is ${sel.nodeIds[0]} doing?`;
    }
    send(q, buildRequest());
  }, [streaming, scopeMode, hasSelection, selection, send, buildRequest]);

  const handleKeyDown = useCallback((e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }, [handleSend]);

  const handleChip = useCallback((chipText) => {
    if (streaming) return;
    const req = buildRequest();
    req.options = { ...req.options, is_simple_question: true };
    send(chipText, req);
  }, [streaming, send, buildRequest]);

  const starterChips = scopeMode === 'selected_entity' && hasSelection
    ? [
        'What is this entity doing?',
        'What protocols does it use?',
        'Who does it talk to most?',
        'Are there any alerts for it?',
      ]
    : [
        'What protocols are in this capture?',
        'Who are the top talkers?',
        'Are there any alerts?',
        'What DNS queries were made?',
      ];

  const providerLabel = settings?.llmProvider === 'openai' ? 'OpenAI-compatible' : 'Ollama';
  const modelLabel    = settings?.llmModel || '—';

  return (
    <div style={{
      display: 'flex', flexDirection: 'column', height: '100%',
      background: 'var(--bgP)', border: '1px solid var(--bdL)', borderRadius: 10,
      overflow: 'hidden', minHeight: 0,
    }}>
      {/* ── Header ── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '10px 14px', borderBottom: '1px solid var(--bd)',
        flexShrink: 0,
      }}>
        <span style={{ fontSize: 15 }}>🤖</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--tx)' }}>LLM Interpretation</div>
          <div style={{ fontSize: 9, color: 'var(--txD)', marginTop: 1 }}>
            {providerLabel} · {modelLabel}
          </div>
        </div>
        <button className="btn" onClick={clear} title="Clear conversation"
          style={{ fontSize: 10, padding: '3px 8px', opacity: turns.length ? 1 : 0.4 }}>
          Clear
        </button>
        <button className="btn" onClick={onOpenSettings} title="LLM settings"
          style={{ fontSize: 10, padding: '3px 8px' }}>
          Settings
        </button>
      </div>

      {/* ── Scope selector ── */}
      <div style={{
        display: 'flex', gap: 4, padding: '8px 14px',
        borderBottom: '1px solid var(--bd)', flexShrink: 0,
      }}>
        {SCOPE_MODES.map(m => {
          const disabled = m.id === 'selected_entity' && !hasSelection;
          const active   = scopeMode === m.id;
          return (
            <button key={m.id}
              disabled={disabled}
              onClick={() => !disabled && setScopeMode(m.id)}
              style={{
                fontSize: 10, padding: '3px 10px', borderRadius: 5, cursor: disabled ? 'not-allowed' : 'pointer',
                border: active ? '1px solid var(--ac)' : '1px solid var(--bd)',
                background: active ? 'rgba(88,166,255,.1)' : 'var(--bgC)',
                color: disabled ? 'var(--txD)' : active ? 'var(--ac)' : 'var(--txM)',
                opacity: disabled ? 0.45 : 1,
              }}>
              {m.label}
            </button>
          );
        })}
        {scopeMode === 'selected_entity' && hasSelection && (
          <span style={{ fontSize: 9, color: 'var(--txD)', alignSelf: 'center', marginLeft: 4 }}>
            {_describeSelection(selection)}
          </span>
        )}
      </div>

      {/* ── Transcript ── */}
      <div ref={transcriptRef} style={{
        flex: 1, overflowY: 'auto', padding: '10px 14px', minHeight: 0,
      }}>
        {turns.length === 0 && (
          <div style={{ paddingTop: 20, textAlign: 'center' }}>
            <div style={{ fontSize: 11, color: 'var(--txD)', lineHeight: 1.65, marginBottom: 14 }}>
              Ask a question about the capture, or try a starter:
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, justifyContent: 'center' }}>
              {starterChips.map(chip => (
                <button key={chip} className="btn" onClick={() => handleChip(chip)}
                  disabled={streaming}
                  style={{ fontSize: 10, padding: '4px 10px', opacity: streaming ? 0.4 : 0.85 }}>
                  {chip}
                </button>
              ))}
            </div>
          </div>
        )}

        {turns.map((turn, i) => (
          <div key={i} style={{ marginBottom: 12 }}>
            {turn.role === 'user' ? (
              <div style={{
                background: 'rgba(88,166,255,.07)', border: '1px solid rgba(88,166,255,.15)',
                borderRadius: 8, padding: '8px 12px',
              }}>
                <div style={{ fontSize: 9, color: 'var(--ac)', marginBottom: 4, fontWeight: 600, letterSpacing: '.05em' }}>YOU</div>
                <div style={{ fontSize: 11, color: 'var(--tx)', lineHeight: 1.65 }}>{turn.content}</div>
              </div>
            ) : (
              <div style={{ paddingLeft: 2 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                  <div style={{ fontSize: 9, color: 'var(--txD)', fontWeight: 600, letterSpacing: '.05em' }}>SWIFTEYE AI</div>
                  {(turn.tags || []).map(t => <TagBadge key={t} tag={t} />)}
                </div>

                {turn.error ? (
                  <div style={{ fontSize: 11, color: '#ff6060', lineHeight: 1.65 }}>
                    Error: {turn.error}
                  </div>
                ) : turn.done ? (
                  <div>{renderMarkdown(turn.content)}</div>
                ) : (
                  /* Still streaming */
                  <div>
                    {renderMarkdown(turn.streamingContent || '')}
                    <span style={{ display: 'inline-block', width: 8, height: 12, background: 'var(--ac)', marginLeft: 2, animation: 'blink 1s step-end infinite', verticalAlign: 'bottom', borderRadius: 1 }} />
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* ── Quick actions ── */}
      <div style={{
        display: 'flex', gap: 6, padding: '6px 14px',
        borderTop: '1px solid var(--bd)', flexShrink: 0,
      }}>
        <button className="btn" onClick={handleExplain} disabled={streaming}
          style={{ fontSize: 10, padding: '4px 10px', opacity: streaming ? 0.5 : 1 }}>
          {scopeMode === 'selected_entity' && hasSelection ? 'Explain this' : 'Explain current view'}
        </button>
      </div>

      {/* ── Input ── */}
      <div style={{
        display: 'flex', gap: 6, padding: '8px 14px',
        borderTop: '1px solid var(--bd)', flexShrink: 0,
      }}>
        <textarea
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Ask a question about this capture… (Enter to send, Shift+Enter for newline)"
          rows={2}
          disabled={streaming}
          style={{
            flex: 1, resize: 'none', background: 'var(--bgH)',
            border: '1px solid var(--bd)', borderRadius: 6,
            padding: '7px 10px', fontSize: 11, color: 'var(--tx)',
            fontFamily: 'var(--fn)', outline: 'none', lineHeight: 1.55,
          }}
        />
        {streaming ? (
          <button className="btn" onClick={cancel}
            style={{ fontSize: 10, padding: '6px 12px', alignSelf: 'flex-end', color: '#ff8080', borderColor: '#ff808040' }}>
            Stop
          </button>
        ) : (
          <button className="btn" onClick={handleSend}
            disabled={!input.trim()}
            style={{ fontSize: 10, padding: '6px 12px', alignSelf: 'flex-end', opacity: input.trim() ? 1 : 0.4 }}>
            Send
          </button>
        )}
      </div>

      {/* Blink animation */}
      <style>{`@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }`}</style>
    </div>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function _inferEntityType(sel) {
  if (!sel) return null;
  if (sel.alertId)   return 'alert';
  if (sel.edgeId)    return 'edge';
  if (sel.sessionId) return 'session';
  if (sel.nodeIds?.length) return 'node';
  return null;
}

function _inferEntityId(sel) {
  if (!sel) return null;
  if (sel.alertId)   return sel.alertId;
  if (sel.edgeId)    return sel.edgeId;
  if (sel.sessionId) return sel.sessionId;
  if (sel.nodeIds?.length) return sel.nodeIds[0];
  return null;
}

function _describeSelection(sel) {
  if (!sel) return '';
  if (sel.alertId)    return `alert: ${sel.alertId}`;
  if (sel.edgeId)     return `edge: ${sel.edgeId.split('|').slice(0, 2).join('↔')}`;
  if (sel.sessionId)  return `session: ${sel.sessionId}`;
  if (sel.nodeIds?.length) return sel.nodeIds.length === 1 ? sel.nodeIds[0] : `${sel.nodeIds.length} nodes`;
  return '';
}
