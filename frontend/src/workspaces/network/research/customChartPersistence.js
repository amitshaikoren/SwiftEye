// ── Custom chart localStorage persistence ─────────────────────────────────────
import { STORAGE_KEYS } from '../../../core/storageKeys';
const CUSTOM_CHARTS_KEY = STORAGE_KEYS.CUSTOM_CHARTS;

export function loadSavedCustomCharts() {
  try {
    return JSON.parse(localStorage.getItem(CUSTOM_CHARTS_KEY) || '[]');
  } catch { return []; }
}

export function saveCustomCharts(configs) {
  try { localStorage.setItem(CUSTOM_CHARTS_KEY, JSON.stringify(configs)); } catch {}
}
