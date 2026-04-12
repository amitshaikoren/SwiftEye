/**
 * useSettings — persistent user preferences via localStorage.
 * Settings are applied globally (CSS class on <body>) and survive page reload.
 *
 * Adding a new setting:
 *  1. Add a key+default to DEFAULTS
 *  2. Add the apply logic to applySettings()
 *  3. Add a control to SettingsPanel.jsx
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { STORAGE_KEYS } from '../storageKeys';
import { fetchLlmKeys, saveLlmKeys } from '../api';

const STORAGE_KEY = STORAGE_KEYS.SETTINGS;

// LLM fields are persisted server-side, not in localStorage
const LLM_FIELDS = ['llmProvider', 'llmBaseUrl', 'llmApiKey', 'llmModel', 'llmTemperature', 'llmMaxTokens'];

// Map server response (snake_case) to settings state keys
function serverToSettings(data) {
  return {
    llmProvider:     data.provider    ?? 'ollama',
    llmBaseUrl:      data.base_url    ?? '',
    llmApiKey:       data.api_key     ?? '',
    llmModel:        data.model       ?? 'qwen2.5:14b-instruct',
    llmTemperature:  data.temperature ?? 0.2,
    llmMaxTokens:    data.max_tokens  ?? 1400,
  };
}

// Map settings state to server request body (snake_case)
function settingsToServer(s) {
  return {
    provider:    s.llmProvider    ?? 'ollama',
    base_url:    s.llmBaseUrl     ?? '',
    api_key:     s.llmApiKey      ?? '',
    model:       s.llmModel       ?? 'qwen2.5:14b-instruct',
    temperature: s.llmTemperature ?? 0.2,
    max_tokens:  s.llmMaxTokens   ?? 1400,
  };
}

export const DEFAULTS = {
  theme:       'dark',  // see THEMES below
  llmProvider: 'ollama',   // 'ollama' | 'openai'
  llmBaseUrl:  '',         // provider base URL (blank = use provider default)
  llmApiKey:   '',         // stored locally, never sent to SwiftEye servers
  llmModel:    'qwen2.5:14b-instruct',
  llmTemperature: 0.2,
  llmMaxTokens:   1400,
};

export const THEMES = [
  { id: 'dark',        label: 'Dark',        desc: 'Default GitHub-dark' },
  { id: 'dark-blue',   label: 'Dark Blue',   desc: 'Deep navy terminal' },
  { id: 'oled',        label: 'OLED Black',  desc: 'Pure black for OLED' },
  { id: 'colorblind',  label: 'Colorblind',  desc: 'Deuteranopia-safe palette' },
  { id: 'blood',       label: 'Blood',       desc: 'Deep crimson' },
  { id: 'amber',       label: 'Amber',       desc: 'Old-school amber monitor' },
  { id: 'synthwave',   label: 'Synthwave',   desc: 'Retro 80s neon purple' },
  { id: 'pastel',      label: 'Pastel',       desc: 'Soft lavender & mint' },
];

function load() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? { ...DEFAULTS, ...JSON.parse(raw) } : { ...DEFAULTS };
  } catch {
    return { ...DEFAULTS };
  }
}

function save(settings) {
  // LLM fields are persisted server-side only — strip them from localStorage
  const local = Object.fromEntries(
    Object.entries(settings).filter(([k]) => !LLM_FIELDS.includes(k))
  );
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(local)); } catch {}
}

// Remove all theme classes then add the active one
const THEME_CLASSES = THEMES.map(t => t.id);
function applySettings(settings) {
  const body = document.body;
  // Remove all theme classes
  THEME_CLASSES.forEach(cls => body.classList.remove(cls));
  // Apply current theme (no class = default dark)
  if (settings.theme && settings.theme !== 'dark') {
    body.classList.add(settings.theme);
  }
}

export function useSettings() {
  const [settings, setSettings] = useState(load);
  const serverLoaded = useRef(false);
  const saveTimer    = useRef(null);

  // Apply theme on mount + whenever settings change
  useEffect(() => {
    applySettings(settings);
  }, [settings]);

  // Load LLM keys from server on mount
  useEffect(() => {
    fetchLlmKeys()
      .then(data => {
        setSettings(prev => ({ ...prev, ...serverToSettings(data) }));
      })
      .catch(() => { /* server unavailable — keep defaults */ })
      .finally(() => { serverLoaded.current = true; });
  }, []);

  // Save LLM keys to server whenever they change (debounced 500 ms)
  // Guard: skip the initial state set triggered by the server load above
  useEffect(() => {
    if (!serverLoaded.current) return;
    clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(() => {
      saveLlmKeys(settingsToServer(settings)).catch(() => {});
    }, 500);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settings.llmProvider, settings.llmBaseUrl, settings.llmApiKey,
      settings.llmModel, settings.llmTemperature, settings.llmMaxTokens]);

  const setSetting = useCallback((key, value) => {
    setSettings(prev => {
      const next = { ...prev, [key]: value };
      save(next);
      return next;
    });
  }, []);

  return { settings, setSetting };
}
