// ── localStorage key registry ─────────────────────────────────────────────────
// All localStorage keys used by SwiftEye must be declared here.
// Import STORAGE_KEYS from this file instead of writing literal strings inline.

export const STORAGE_KEYS = {
  SETTINGS:          'swifteye_settings',
  CUSTOM_CHARTS:     'swifteye_custom_charts',
  SCOPE_NODE:        'swifteye_scope_node',
  SCOPE_EDGE:        'swifteye_scope_edge',
  SCOPE_SLOT_PREFIX: 'swifteye_scope_slot_',
  scopeSlot: (id)  => `swifteye_scope_slot_${id || 'default'}`,
};
