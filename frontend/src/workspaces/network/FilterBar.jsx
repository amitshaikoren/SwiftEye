/**
 * FilterBar — Wireshark-style display filter bar.
 *
 * Lives in its own horizontal bar between TopBar and the main content area.
 * Evaluates expressions against the current graph client-side.
 *
 * Props:
 *   value        string   current expression
 *   onChange     fn(str)  called on every keystroke (for controlled input)
 *   onApply      fn(str)  called when Enter pressed or Apply clicked
 *   onClear      fn()     called when filter is cleared
 *   matchCount   number|null   how many nodes matched (null = not applied yet)
 *   error        string|null   parse/eval error to display
 *   isActive     bool     whether a filter is currently applied
 *   osGuesses    string[] OS families detected in current graph (for quick chips)
 *   activeOsFilter string  current active OS filter expression (to highlight chip)
 */

import React, { useState, useRef, useEffect, useMemo } from 'react';
import { useWorkspace } from '@/WorkspaceProvider';
import { schemaFilterTokens, schemaHelpRows } from '@core/schema';

export default function FilterBar({ value, onChange, onApply, onClear, matchCount, error, isActive, osGuesses = [], activeOsFilter = '' }) {
  const workspace = useWorkspace();
  const [showHelp, setShowHelp] = useState(false);
  const [suggestions, setSuggestions] = useState([]);
  const [suggIdx, setSuggIdx] = useState(-1);
  const inputRef = useRef(null);
  const helpRef = useRef(null);

  // Autocomplete tokens: schema filter paths + declared bare flags + the
  // workspace's protocol-shorthand extras (http / tcp / etc.).
  const FIELD_SUGGESTIONS = useMemo(() => {
    const base = schemaFilterTokens(workspace.schema);
    const extras = workspace.filterSuggestions || [];
    return [...new Set([...base, ...extras])];
  }, [workspace]);

  const EXAMPLES = workspace.filterExamples || [];
  const HELP_ROWS = useMemo(() => schemaHelpRows(workspace.schema), [workspace]);

  // Close help on outside click
  useEffect(() => {
    function handler(e) {
      if (helpRef.current && !helpRef.current.contains(e.target)) {
        setShowHelp(false);
      }
    }
    if (showHelp) document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [showHelp]);

  function handleKey(e) {
    if (suggestions.length > 0) {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSuggIdx(i => Math.min(i + 1, suggestions.length - 1));
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSuggIdx(i => Math.max(i - 1, -1));
        return;
      }
      if (e.key === 'Tab' || (e.key === 'Enter' && suggIdx >= 0)) {
        e.preventDefault();
        applySuggestion(suggestions[suggIdx >= 0 ? suggIdx : 0]);
        return;
      }
      if (e.key === 'Escape') {
        setSuggestions([]);
        setSuggIdx(-1);
        return;
      }
    }
    if (e.key === 'Enter') {
      setSuggestions([]);
      onApply(value);
    }
    if (e.key === 'Escape' && !suggestions.length) {
      onClear();
    }
  }

  function handleChange(e) {
    const v = e.target.value;
    onChange(v);
    // Generate autocomplete suggestions for the current word
    const beforeCursor = v.slice(0, e.target.selectionStart);
    const wordMatch = beforeCursor.match(/[\w.]+$/);
    const word = wordMatch ? wordMatch[0].toLowerCase() : '';
    if (word.length >= 1) {
      const matches = FIELD_SUGGESTIONS.filter(s => s.startsWith(word) && s !== word);
      setSuggestions(matches.slice(0, 6));
      setSuggIdx(-1);
    } else {
      setSuggestions([]);
    }
  }

  function applySuggestion(sugg) {
    // Replace the current partial word with the suggestion
    const input = inputRef.current;
    const pos = input.selectionStart;
    const before = value.slice(0, pos);
    const after = value.slice(pos);
    const wordMatch = before.match(/[\w.]+$/);
    const newBefore = wordMatch ? before.slice(0, before.length - wordMatch[0].length) + sugg : before + sugg;
    const newVal = newBefore + after;
    onChange(newVal);
    setSuggestions([]);
    setSuggIdx(-1);
    setTimeout(() => {
      input.focus();
      input.setSelectionRange(newBefore.length, newBefore.length);
    }, 0);
  }

  function handleOsChip(os) {
    const keyword = os.split(' ')[0];
    const expr = `os contains "${keyword}"`;
    const isOn = activeOsFilter.includes(keyword);
    if (isOn) {
      onChange('');
      onClear();
    } else {
      onChange(expr);
      onApply(expr);
    }
  }

  const borderColor = error ? 'var(--acR)' : isActive ? 'var(--ac)' : 'var(--bd)';
  const bgColor = error ? 'rgba(248,81,73,.06)' : isActive ? 'rgba(88,166,255,.06)' : 'var(--bgI)';

  return (
    <div style={{
      background: 'var(--bgP)', borderBottom: '1px solid var(--bd)',
      padding: '5px 12px', flexShrink: 0,
      position: 'relative', zIndex: 20,
    }}>
      {/* Main filter row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {/* Filter icon */}
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
          stroke={isActive ? 'var(--ac)' : 'var(--txD)'} strokeWidth="2" style={{ flexShrink: 0 }}>
          <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/>
        </svg>

        {/* Input + suggestions */}
        <div style={{ flex: 1, position: 'relative' }}>
          <input
            ref={inputRef}
            value={value}
            onChange={handleChange}
            onKeyDown={handleKey}
            onBlur={() => setTimeout(() => setSuggestions([]), 150)}
            placeholder='Display filter  ·  e.g.  http  ·  ip == 10.0.0.1  ·  tcp && port == 443  ·  tls.sni contains "google"'
            spellCheck={false}
            autoComplete="off"
            style={{
              width: '100%', padding: '4px 8px', fontSize: 11,
              fontFamily: 'var(--fn)', background: bgColor,
              border: `1px solid ${borderColor}`,
              borderRadius: 'var(--r)', color: 'var(--tx)',
              outline: 'none', transition: 'border-color .15s, background .15s',
              boxSizing: 'border-box',
            }}
          />

          {/* Autocomplete dropdown */}
          {suggestions.length > 0 && (
            <div style={{
              position: 'absolute', top: '100%', left: 0, zIndex: 100,
              background: 'var(--bgP)', border: '1px solid var(--bd)',
              borderRadius: 'var(--r)', marginTop: 2, minWidth: 160,
              boxShadow: '0 4px 16px rgba(0,0,0,.4)',
              overflow: 'hidden',
            }}>
              {suggestions.map((s, i) => (
                <div key={s}
                  onMouseDown={() => applySuggestion(s)}
                  style={{
                    padding: '5px 10px', fontSize: 11, cursor: 'pointer',
                    fontFamily: 'var(--fn)',
                    background: i === suggIdx ? 'rgba(88,166,255,.12)' : 'transparent',
                    color: i === suggIdx ? 'var(--ac)' : 'var(--txM)',
                  }}
                  onMouseEnter={() => setSuggIdx(i)}
                >{s}</div>
              ))}
            </div>
          )}
        </div>

        {/* Status / error */}
        <div style={{ minWidth: 80, fontSize: 10, fontFamily: 'var(--fn)', flexShrink: 0 }}>
          {error ? (
            <span style={{ color: 'var(--acR)' }} title={error}>
              ✕ {error.length > 28 ? error.slice(0, 28) + '…' : error}
            </span>
          ) : isActive && matchCount !== null ? (
            <span style={{ color: 'var(--ac)' }}>
              {matchCount} node{matchCount !== 1 ? 's' : ''}
            </span>
          ) : null}
        </div>

        {/* Apply button */}
        <button
          className={'btn' + (isActive ? ' on' : '')}
          onClick={() => onApply(value)}
          style={{ fontSize: 10, padding: '3px 10px' }}
        >Apply</button>

        {/* Clear button — only when active */}
        {(isActive || value) && (
          <button
            className="btn"
            onClick={() => { onChange(''); onClear(); setSuggestions([]); }}
            style={{ fontSize: 10, padding: '3px 8px', color: 'var(--txD)' }}
            title="Clear filter (Esc)"
          >✕</button>
        )}

        {/* Help toggle */}
        <div style={{ position: 'relative' }} ref={helpRef}>
          <button
            className={'btn' + (showHelp ? ' on' : '')}
            onClick={() => setShowHelp(v => !v)}
            style={{ fontSize: 10, padding: '3px 8px' }}
            title="Filter syntax help"
          >?</button>

          {showHelp && (
            <div style={{
              position: 'absolute', top: '100%', right: 0, zIndex: 200,
              background: 'var(--bgP)', border: '1px solid var(--bd)',
              borderRadius: 6, marginTop: 4, width: 340, padding: '12px 14px',
              boxShadow: '0 8px 32px rgba(0,0,0,.5)',
              fontSize: 11, color: 'var(--txM)', lineHeight: 1.6,
              maxHeight: 'calc(100vh - 100px)', overflowY: 'auto',
            }}>
              <div style={{ fontWeight: 600, color: 'var(--tx)', marginBottom: 8, fontSize: 12 }}>
                Display Filter Syntax
              </div>

              <div style={{ color: 'var(--txD)', marginBottom: 6, fontSize: 10 }}>FIELDS</div>
              <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 10 }}>
                <tbody>
                  {HELP_ROWS.map(({ filter_path, description }) => (
                    <tr key={filter_path}>
                      <td style={{ fontFamily: 'var(--fn)', color: 'var(--ac)', paddingRight: 10, verticalAlign: 'top', whiteSpace: 'nowrap' }}>{filter_path}</td>
                      <td style={{ color: 'var(--txD)', fontSize: 10 }}>{description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <div style={{ color: 'var(--txD)', marginBottom: 6, fontSize: 10 }}>OPERATORS</div>
              <div style={{ fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--txM)', marginBottom: 10 }}>
                == &nbsp; != &nbsp; &gt; &nbsp; &lt; &nbsp; &gt;= &nbsp; &lt;= &nbsp; contains &nbsp; matches
              </div>

              <div style={{ color: 'var(--txD)', marginBottom: 6, fontSize: 10 }}>COMBINATORS</div>
              <div style={{ fontFamily: 'var(--fn)', fontSize: 10, color: 'var(--txM)', marginBottom: 10 }}>
                expr1 &amp;&amp; expr2 &nbsp;·&nbsp; expr1 || expr2 &nbsp;·&nbsp; !expr &nbsp;·&nbsp; ( expr )
              </div>

              <div style={{ color: 'var(--txD)', marginBottom: 6, fontSize: 10 }}>EXAMPLES</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                {EXAMPLES.map(({ label, expr }) => (
                  <div key={expr} style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}>
                    <span
                      onClick={() => { onChange(expr); onApply(expr); setShowHelp(false); }}
                      style={{
                        fontFamily: 'var(--fn)', color: 'var(--ac)', cursor: 'pointer',
                        fontSize: 10, flexShrink: 0,
                      }}
                      title="Click to apply"
                    >{expr}</span>
                    <span style={{ color: 'var(--txD)', fontSize: 10 }}>{label}</span>
                  </div>
                ))}
              </div>

              <div style={{ marginTop: 10, borderTop: '1px solid var(--bd)', paddingTop: 8, fontSize: 10, color: 'var(--txD)' }}>
                Bare protocol names (http, dns, ssh…) match nodes or edges with that protocol.
                CIDR notation supported: ip == 10.0.0.0/8.
                Press Enter to apply · Esc to clear.
              </div>
            </div>
          )}
        </div>
      </div>

      {/* OS quick-filter chips — grouped by family, one chip per OS keyword */}
      {osGuesses.length > 0 && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 5, marginTop: 4,
          paddingTop: 4, borderTop: '1px solid rgba(128,128,128,0.08)',
        }}>
          <span style={{ fontSize: 9, color: 'var(--txD)', flexShrink: 0, letterSpacing: '.05em' }}>OS:</span>
          {(() => {
            // Group OS guesses by family keyword to avoid redundant chips
            // e.g. "Windows 10/11", "Windows (likely)" → one "Windows" chip
            const families = new Map();
            for (const os of osGuesses) {
              const keyword = os.split(' ')[0];
              if (!families.has(keyword)) families.set(keyword, []);
              families.get(keyword).push(os);
            }
            return [...families.entries()].map(([keyword, variants]) => {
              const isOn = activeOsFilter.includes(keyword);
              const label = variants.length === 1 ? variants[0] : `${keyword} (${variants.length})`;
              return (
                <button
                  key={keyword}
                  onClick={() => handleOsChip(variants[0])}
                  title={variants.length === 1
                    ? `Filter: os contains "${keyword}"`
                    : `Filter: os contains "${keyword}" — matches: ${variants.join(', ')}`}
                  style={{
                    padding: '1px 7px', fontSize: 9, borderRadius: 10,
                    cursor: 'pointer', border: '1px solid',
                    fontFamily: 'var(--fn)', transition: 'all .12s',
                    background: isOn ? 'rgba(88,166,255,.15)' : 'transparent',
                    borderColor: isOn ? 'var(--ac)' : 'var(--bd)',
                    color: isOn ? 'var(--ac)' : 'var(--txD)',
                  }}
                >{label}</button>
              );
            });
          })()}
          {activeOsFilter && (
            <button
              onClick={() => { onChange(''); onClear(); }}
              style={{
                padding: '1px 5px', fontSize: 9, cursor: 'pointer',
                background: 'none', border: 'none', color: 'var(--txD)',
                marginLeft: 2,
              }}
              title="Clear OS filter"
            >✕</button>
          )}
        </div>
      )}
    </div>
  );
}
