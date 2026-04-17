/**
 * FilterContext — centralized, observable global filter state.
 *
 * Provides the current filter as a single canonical object to any component
 * that calls useFilterContext(), without prop drilling.
 *
 * The actual filter state lives in useCapture(). This context is the read side:
 * App.jsx builds the value from useCapture() and provides it here.
 * Setters (setTimeRange, setEnabledP, etc.) remain on the `c` object from useCapture().
 *
 * Shape:
 *   timeRange           — [startIdx, endIdx] current slider indices
 *   enabledP            — Set of composite keys ("4/TCP/HTTPS") for graph-level filtering
 *   search              — string, current search text
 *   includeIPv6         — bool
 *   protocolList        — string[], actual protocols in the loaded capture (from /api/protocols)
 *   allProtocolKeysCount — number, total composite key count (for "all enabled" check)
 */

import { createContext, useContext } from 'react';

export const FilterContext = createContext(null);

export function useFilterContext() {
  const ctx = useContext(FilterContext);
  if (!ctx) throw new Error('useFilterContext must be used inside FilterContext.Provider');
  return ctx;
}

/**
 * Convert composite protocol keys to simple protocol names for API calls.
 *
 * Composite keys carry ipVersion/transport/appProtocol (e.g. "4/TCP/HTTPS").
 * Research charts and session filters only need the last segment ("HTTPS").
 * TCP/UDP transport distinction is intentionally lost here — acceptable for
 * research and session contexts where protocol-name filtering is sufficient.
 *
 * Returns '' when all protocols are enabled (no filter needed),
 * or a comma-separated list of deduplicated names otherwise.
 */
export function toProtocolNames(enabledP, allProtocolKeysCount) {
  if (!enabledP || enabledP.size === 0 || enabledP.size >= allProtocolKeysCount) return '';
  const names = [...new Set([...enabledP].map(k => k.split('/').at(-1)))];
  return names.join(',');
}

/**
 * Apply the global filter to a session list (client-side).
 * Used by NodeDetail and EdgeDetail in SCOPED mode.
 */
export function applyDisplayFilter(sessions, filterCtx) {
  if (!filterCtx) return sessions;
  const { enabledP, allProtocolKeysCount, search, includeIPv6 } = filterCtx;
  let result = sessions;
  if (!includeIPv6) {
    result = result.filter(s => !s.src_ip.includes(':') && !s.dst_ip.includes(':'));
  }
  if (enabledP.size > 0 && enabledP.size < allProtocolKeysCount) {
    const appProtos = new Set([...enabledP].map(k => k.split('/').pop().toUpperCase()));
    result = result.filter(s => appProtos.has((s.protocol || '').toUpperCase()));
  }
  if (search.trim()) {
    const q = search.toLowerCase();
    result = result.filter(s =>
      s.src_ip.toLowerCase().includes(q) ||
      s.dst_ip.toLowerCase().includes(q) ||
      (s.protocol || '').toLowerCase().includes(q) ||
      String(s.src_port).includes(q) ||
      String(s.dst_port).includes(q)
    );
  }
  return result;
}
