import React from 'react';
import { THEMES } from '../hooks/useSettings';

export default function SettingsPanel({ settings, setSetting, onClose }) {
  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      display: 'flex', alignItems: 'flex-start', justifyContent: 'flex-end',
    }} onClick={onClose}>
      {/* Panel */}
      <div onClick={e => e.stopPropagation()} style={{
        width: 300, height: '100vh', background: 'var(--bgP)',
        borderLeft: '1px solid var(--bd)', overflowY: 'auto',
        padding: 20, boxShadow: '-4px 0 24px rgba(0,0,0,0.4)',
      }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--tx)' }}>Settings</div>
          <button className="btn" onClick={onClose}>✕</button>
        </div>

        {/* Theme */}
        <div style={{ marginBottom: 24 }}>
          <div style={{
            fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase',
            letterSpacing: '.08em', marginBottom: 10,
          }}>Theme</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {THEMES.map(theme => {
              const active = settings.theme === theme.id;
              return (
                <button key={theme.id} onClick={() => setSetting('theme', theme.id)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 10,
                    padding: '8px 10px', borderRadius: 6, cursor: 'pointer',
                    border: active ? '1px solid var(--ac)' : '1px solid var(--bd)',
                    background: active ? 'rgba(88,166,255,0.08)' : 'var(--bgC)',
                    textAlign: 'left', width: '100%',
                  }}>
                  {/* Colour swatch */}
                  <span style={{
                    width: 24, height: 24, borderRadius: 4, flexShrink: 0,
                    background: THEME_SWATCH[theme.id] || '#0e1117',
                    border: '1px solid rgba(255,255,255,0.1)',
                    display: 'inline-block',
                  }} />
                  <span style={{ flex: 1 }}>
                    <span style={{ fontSize: 11, fontWeight: 500, color: 'var(--tx)', display: 'block' }}>
                      {theme.label}
                    </span>
                    <span style={{ fontSize: 9, color: 'var(--txD)' }}>{theme.desc}</span>
                  </span>
                  {active && (
                    <span style={{ fontSize: 10, color: 'var(--ac)' }}>✓</span>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* LLM Provider */}
        <div style={{ marginBottom: 24 }}>
          <div style={{
            fontSize: 9, color: 'var(--txD)', textTransform: 'uppercase',
            letterSpacing: '.08em', marginBottom: 10,
          }}>LLM Provider</div>

          {/* Provider selector */}
          <div style={{ marginBottom: 8 }}>
            <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 4 }}>Provider</div>
            <select value={settings.llmProvider || 'ollama'}
              onChange={e => setSetting('llmProvider', e.target.value)}
              style={{ width: '100%', background: 'var(--bgH)', border: '1px solid var(--bd)', borderRadius: 5, padding: '6px 8px', fontSize: 11, color: 'var(--tx)', outline: 'none', cursor: 'pointer' }}>
              <option value="ollama">Ollama (local, no key required)</option>
              <option value="openai">OpenAI-compatible</option>
            </select>
          </div>

          {/* Base URL */}
          <div style={{ marginBottom: 8 }}>
            <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 4 }}>
              Base URL <span style={{ color: 'var(--txD)' }}>(blank = provider default)</span>
            </div>
            <input type="text"
              value={settings.llmBaseUrl || ''}
              onChange={e => setSetting('llmBaseUrl', e.target.value)}
              placeholder={settings.llmProvider === 'ollama' ? 'http://localhost:11434' : 'https://api.openai.com/v1'}
              style={{ width: '100%', boxSizing: 'border-box', background: 'var(--bgH)', border: '1px solid var(--bd)', borderRadius: 5, padding: '6px 8px', fontSize: 11, color: 'var(--tx)', fontFamily: 'var(--fn)', outline: 'none' }} />
          </div>

          {/* Model */}
          <div style={{ marginBottom: 8 }}>
            <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 4 }}>Model</div>
            <input type="text"
              value={settings.llmModel || ''}
              onChange={e => setSetting('llmModel', e.target.value)}
              placeholder={settings.llmProvider === 'ollama' ? 'qwen2.5:14b-instruct' : 'gpt-4o-mini'}
              style={{ width: '100%', boxSizing: 'border-box', background: 'var(--bgH)', border: '1px solid var(--bd)', borderRadius: 5, padding: '6px 8px', fontSize: 11, color: 'var(--tx)', fontFamily: 'var(--fn)', outline: 'none' }} />
          </div>

          {/* API Key (only shown for openai) */}
          {settings.llmProvider === 'openai' && (
            <div style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 10, color: 'var(--txM)', marginBottom: 4 }}>API Key</div>
              <input type="password"
                value={settings.llmApiKey || ''}
                onChange={e => setSetting('llmApiKey', e.target.value)}
                placeholder="sk-…"
                style={{ width: '100%', boxSizing: 'border-box', background: 'var(--bgH)', border: '1px solid var(--bd)', borderRadius: 5, padding: '6px 8px', fontSize: 11, color: 'var(--tx)', fontFamily: 'var(--fn)', outline: 'none' }} />
            </div>
          )}

          {/* Privacy note */}
          <div style={{ fontSize: 9, color: 'var(--txD)', lineHeight: 1.55, marginTop: 6 }}>
            {settings.llmProvider === 'openai'
              ? 'Your API key is stored only in this browser. Capture-derived context is sent to the external provider when you ask a question.'
              : 'Ollama runs locally. No data leaves your machine.'}
          </div>
        </div>

        {/* Footer */}
        <div style={{ fontSize: 9, color: 'var(--txD)', borderTop: '1px solid var(--bd)', paddingTop: 12 }}>
          Settings are saved automatically in your browser.
        </div>
      </div>
    </div>
  );
}

// Representative background colour for each theme swatch
const THEME_SWATCH = {
  'dark':       '#0e1117',
  'dark-blue':  '#0a1929',
  'oled':       '#000000',
  'colorblind': '#0e1117',
  'blood':      '#130608',
  'amber':      '#130f00',
  'synthwave':  '#12011d',
  'pastel':     '#201c30',
};
