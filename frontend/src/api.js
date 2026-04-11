/**
 * SwiftEye API client.
 * All backend communication flows through here.
 */

const API = '';

export async function api(path, opts) {
  const r = await fetch(API + path, opts);
  if (!r.ok) {
    const e = await r.json().catch(() => ({ detail: r.statusText }));
    throw new Error(e.detail || e.error || 'Failed');
  }
  return r.json();
}

export async function uploadPcap(files, forceAdapter = null) {
  const form = new FormData();
  const fileList = Array.isArray(files) ? files : [files];
  for (const f of fileList) form.append('files', f);
  if (forceAdapter) form.append('force_adapter', forceAdapter);
  return api('/api/upload', { method: 'POST', body: form });
}

export async function confirmSchemaMapping(stagingToken, mapping) {
  return api('/api/upload/confirm-schema', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ staging_token: stagingToken, mapping }),
  });
}

export async function fetchStats(params = {}) {
  const p = new URLSearchParams();
  if (params.timeStart != null) p.set('time_start', params.timeStart);
  if (params.timeEnd   != null) p.set('time_end',   params.timeEnd);
  const qs = p.toString();
  return api(`/api/stats${qs ? '?' + qs : ''}`);
}

export async function fetchTimeline(bucketSeconds = 15) {
  return api(`/api/timeline?bucket_seconds=${bucketSeconds}`);
}

export async function fetchGraph(params = {}, signal) {
  const p = new URLSearchParams();
  if (params.timeStart != null) p.set('time_start', params.timeStart);
  if (params.timeEnd != null) p.set('time_end', params.timeEnd);
  if (params.protocols) p.set('protocols', params.protocols);
  if (params.protocolFilters) p.set('protocol_filters', params.protocolFilters);
  if (params.ipFilter) p.set('ip_filter', params.ipFilter);
  if (params.portFilter) p.set('port_filter', params.portFilter);
  if (params.search) p.set('search', params.search);
  if (params.subnetGrouping) {
    p.set('subnet_grouping', 'true');
    p.set('subnet_prefix', params.subnetPrefix ?? 24);
  }
  if (params.mergeByMac)     p.set('merge_by_mac',     'true');
  if (params.includeIPv6 === false) p.set('include_ipv6', 'false');
  if (params.showHostnames === false) p.set('show_hostnames', 'false');
  if (params.excludeBroadcasts) p.set('exclude_broadcasts', 'true');
  if (params.subnetExclusions && params.subnetExclusions.size > 0)
    p.set('subnet_exclusions', Array.from(params.subnetExclusions).join(','));
  if (params.clusterAlgorithm) {
    p.set('cluster_algorithm', params.clusterAlgorithm);
    if (params.clusterResolution != null) p.set('cluster_resolution', params.clusterResolution);
  }
  return api(`/api/graph?${p}`, signal ? { signal } : undefined);
}

export async function fetchSessions(limit = 1000, search = '', timeParams = {}) {
  const p = new URLSearchParams({ limit });
  if (search) p.set('search', search);
  if (timeParams.timeStart != null) p.set('time_start', timeParams.timeStart);
  if (timeParams.timeEnd   != null) p.set('time_end',   timeParams.timeEnd);
  return api(`/api/sessions?${p}`);
}

export async function fetchEdgeSessions(edgeId, { sortBy = 'bytes', limit = 500 } = {}) {
  const p = new URLSearchParams({ edge_id: edgeId, sort_by: sortBy, limit });
  return api(`/api/edge-sessions?${p}`);
}

export async function fetchEdgeDetail(edgeId, graphParams = {}) {
  // graphParams mirrors the filter params passed to fetchGraph so the detail
  // reflects the same filtered view the user was looking at.
  const p = new URLSearchParams();
  if (graphParams.timeStart  != null) p.set('time_start',        graphParams.timeStart);
  if (graphParams.timeEnd    != null) p.set('time_end',          graphParams.timeEnd);
  if (graphParams.protocols)          p.set('protocols',         graphParams.protocols);
  if (graphParams.subnetGrouping)     p.set('subnet_grouping',   'true');
  if (graphParams.subnetPrefix != null) p.set('subnet_prefix',   graphParams.subnetPrefix);
  if (graphParams.mergeByMac)         p.set('merge_by_mac',      'true');
  if (graphParams.includeIPv6 === false) p.set('include_ipv6',   'false');
  if (graphParams.excludeBroadcasts)  p.set('exclude_broadcasts','true');
  if (graphParams.subnetExclusions)   p.set('subnet_exclusions', graphParams.subnetExclusions);
  const qs = p.toString();
  return api(`/api/edge/${encodeURIComponent(edgeId)}/detail${qs ? '?' + qs : ''}`);
}

export async function fetchEdgeFieldMeta() {
  return api('/api/meta/edge-fields').catch(() => ({ fields: [] }));
}

export async function fetchPaths(source, target, { cutoff = 5, maxPaths = 10, directed = false } = {}) {
  const p = new URLSearchParams({ source, target, cutoff, max_paths: maxPaths, directed });
  return api(`/api/paths?${p}`);
}

export async function fetchSessionDetail(sessionId, packetLimit = 200) {
  // Mirror backend Query constraint (data.py: ge=1, le=50000) so no caller can 422 us.
  const lim = Math.max(1, Math.min(50000, packetLimit | 0));
  return api(`/api/session_detail?session_id=${encodeURIComponent(sessionId)}&packet_limit=${lim}`);
}

export async function fetchProtocols() {
  return api('/api/protocols');
}

export async function fetchPluginResults() {
  // Intentional catch: plugin results are empty until a capture is loaded and
  // plugins have run. Returning {} is the correct fallback — no capture = no results.
  return api('/api/plugins/results').catch(() => ({ results: {} }));
}

export async function fetchPluginSlots() {
  // Does not require a capture — plugin slot declarations are static server metadata.
  return api('/api/plugins');
}

export function slicePcapUrl(params = {}) {
  // Returns a URL for direct download (used as href on an <a> tag).
  // Mirrors the filter params used by fetchGraph.
  const p = new URLSearchParams();
  if (params.timeStart != null) p.set('time_start', params.timeStart);
  if (params.timeEnd   != null) p.set('time_end',   params.timeEnd);
  if (params.protocols) p.set('protocols', params.protocols);
  if (params.search)    p.set('search',    params.search);
  if (params.includeIPv6 === false) p.set('include_ipv6', 'false');
  if (params.showHostnames === false) p.set('show_hostnames', 'false');
  return `/api/slice?${p}`;
}

export async function fetchLogs(last = 80) {
  return api(`/api/logs?last=${last}`);
}

export async function fetchStatus() {
  return api('/api/status');
}

export async function uploadMetadata(file) {
  const form = new FormData();
  form.append('file', file);
  return api('/api/metadata', { method: 'POST', body: form });
}

export async function fetchHostnames() {
  return api('/api/hostnames');
}

export async function fetchResearchCharts() {
  // Does not require a capture — chart list is static server metadata.
  // Do not swallow errors here; let ResearchPage handle them explicitly.
  return api('/api/research');
}

export async function runResearchChart(chartName, params) {
  return api(`/api/research/${chartName}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
}

export async function fetchCustomChartSchema() {
  return api('/api/research/custom/schema');
}

export async function runCustomChart(payload) {
  return api('/api/research/custom', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

// ── Query ────────────────────────────────────────────────────────────────────

export async function runQuery(query) {
  return api('/api/query', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(query),
  });
}

export async function parseQueryText(text, dialect) {
  return api('/api/query/parse', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, dialect: dialect || undefined }),
  });
}

export async function fetchQuerySchema() {
  return api('/api/query/schema').catch(() => ({ node_fields: {}, edge_fields: {} }));
}

// ── Analysis ────────────────────────────────────────────────────────────────

export async function fetchAnalysisResults() {
  return api('/api/analysis/results').catch(() => ({ results: {} }));
}

// ── Investigation ───────────────────────────────────────────────────────────

export async function fetchInvestigation() {
  return api('/api/investigation').catch(() => ({ markdown: '', images: {} }));
}

export async function saveInvestigation(markdown) {
  return api('/api/investigation', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ markdown }),
  });
}

export async function uploadInvestigationImage(file) {
  const form = new FormData();
  form.append('file', file);
  return api('/api/investigation/image', { method: 'POST', body: form });
}

// ── Annotations ──────────────────────────────────────────────────────────────

export async function fetchAnnotations() {
  // Intentional catch: annotations are per-capture state. Empty is correct before load.
  return api('/api/annotations').catch(() => ({ annotations: [] }));
}

export async function createAnnotation(annotation) {
  return api('/api/annotations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(annotation),
  });
}

export async function updateAnnotation(id, updates) {
  return api(`/api/annotations/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates),
  });
}

export async function deleteAnnotation(id) {
  return api(`/api/annotations/${id}`, { method: 'DELETE' });
}

// ── Synthetic nodes/edges ────────────────────────────────────────────────────

export async function fetchSynthetic() {
  // Intentional catch: synthetic elements are per-capture state. Empty is correct before load.
  return api('/api/synthetic').catch(() => ({ synthetic: [] }));
}

export async function createSynthetic(obj) {
  return api('/api/synthetic', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(obj),
  });
}

export async function updateSynthetic(id, updates) {
  return api(`/api/synthetic/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates),
  });
}

export async function deleteSynthetic(id) {
  return api(`/api/synthetic/${id}`, { method: 'DELETE' });
}

export async function clearSynthetic() {
  return api('/api/synthetic', { method: 'DELETE' });
}

export async function fetchAlerts() {
  return api('/api/alerts').catch(() => ({ alerts: [], summary: {} }));
}

// ── LLM Interpretation ───────────────────────────────────────────────────────

/**
 * Stream a chat response from the LLM interpretation endpoint.
 *
 * @param {object} request  - Full ChatRequest body (messages, scope, viewer_state, selection, provider, options)
 * @param {function} onEvent - Called with each parsed event object as it arrives
 * @param {AbortSignal} [signal] - Optional AbortSignal for cancellation
 * @returns {Promise<void>}
 */
export async function streamLlmChat(request, onEvent, signal) {
  const resp = await fetch('/api/llm/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
    signal,
  });

  if (!resp.ok) {
    let msg = resp.statusText;
    try { const e = await resp.json(); msg = e.detail || e.error || msg; } catch {}
    throw new Error(msg);
  }

  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const event = JSON.parse(trimmed);
        onEvent(event);
      } catch {
        // Malformed line — skip silently
      }
    }
  }

  // Flush remaining buffer
  if (buffer.trim()) {
    try { onEvent(JSON.parse(buffer.trim())); } catch {}
  }
}

export async function fetchNodeAnimation(nodeIds, protocols) {
  const p = new URLSearchParams();
  p.set('nodes', nodeIds.join(','));
  if (protocols) p.set('protocols', protocols);
  return api(`/api/node-animation?${p}`);
}
