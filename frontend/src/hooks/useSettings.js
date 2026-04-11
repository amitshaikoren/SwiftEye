/**
 * useSettings — persistent user preferences via localStorage.
 * Settings are applied globally (CSS class on <body>) and survive page reload.
 *
 * Adding a new setting:
 *  1. Add a key+default to DEFAULTS
 *  2. Add the apply logic to applySettings()
 *  3. Add a control to SettingsPanel.jsx
 */

import { useState, useEffect, useCallback } from 'react';
import { STORAGE_KEYS } from '../storageKeys';

const STORAGE_KEY = STORAGE_KEYS.SETTINGS;

export const DEFAULTS = {
  theme:    'dark',  // see THEMES below
  llmApiKey: '',     // stored locally, never sent to SwiftEye servers
  llmModel: 'gpt-4o-mini',
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
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(settings)); } catch {}
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

  // Apply on mount + whenever settings change
  useEffect(() => {
    applySettings(settings);
  }, [settings]);

  const setSetting = useCallback((key, value) => {
    setSettings(prev => {
      const next = { ...prev, [key]: value };
      save(next);
      return next;
    });
  }, []);

  return { settings, setSetting };
}
