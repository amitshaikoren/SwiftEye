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

export async function uploadPcap(files) {
  const form = new FormData();
  const fileList = Array.isArray(files) ? files : [files];
  for (const f of fileList) form.append('files', f);
  return api('/api/upload', { method: 'POST', body: form });
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
  if (params.subnetExclusions && params.subnetExclusions.size > 0)
    p.set('subnet_exclusions', Array.from(params.subnetExclusions).join(','));
  return api(`/api/graph?${p}`, signal ? { signal } : undefined);
}

export async function fetchSessions(limit = 1000, search = '', timeParams = {}) {
  const p = new URLSearchParams({ limit });
  if (search) p.set('search', search);
  if (timeParams.timeStart != null) p.set('time_start', timeParams.timeStart);
  if (timeParams.timeEnd   != null) p.set('time_end',   timeParams.timeEnd);
  return api(`/api/sessions?${p}`);
}

export async function fetchSessionDetail(sessionId, packetLimit = 200) {
  return api(`/api/session_detail?session_id=${encodeURIComponent(sessionId)}&packet_limit=${packetLimit}`);
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

export function investigationExportUrl() {
  return '/api/investigation/export';
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
