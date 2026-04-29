/**
 * Network workspace — registration object.
 *
 * `enrichEdge(edge, srcNode, dstNode)` returns extra synthetic wire keys
 * that the schema declares on flow edges (`_srcIp`, `_dstIp`,
 * `_endpointIps`). Core's display-filter pass calls this during edge
 * enrichment — keeping all "flow endpoint = host IP" knowledge inside the
 * network workspace so `core/` stays network-agnostic.
 *
 * `filterSuggestions` extends FilterBar autocomplete with protocol
 * shorthand (http, https, dns, tcp, …). `filterExamples` are the
 * example expressions shown in the filter-help popover. Both are
 * workspace-specific copy, declared here so FilterBar doesn't hardcode.
 *
 * `NodeDetail` / `EdgeDetail` are the right-panel components for a
 * single-host / single-flow selection. Core's `AppRightPanel` pulls
 * them off the descriptor so `core/` carries no hardcoded reference
 * to the network panels. Panel internals stay network-specific (Q3
 * sign-off: shallow refactor for phase 2 — full schema-driven node-
 * detail contract is deferred to `node-detail-contract.md`).
 */

import NodeDetail from './NodeDetail';
import EdgeDetail from './EdgeDetail';
import FilterBar from './FilterBar';
import UploadScreen from './UploadScreen';
import { matchSessionToEdge } from './sessionMatch';
import {
  fetchEdgeFieldMeta, fetchTimeline, fetchSessions, fetchStats,
  fetchProtocols, fetchPluginResults, fetchPluginSlots,
  fetchAnnotations, fetchSynthetic, fetchAlerts,
} from '@core/api';

const SESSIONS_FETCH_LIMIT = 1000;

// Hint-keyword → edge-field flag aliasing. Lives here (not in core/) because
// the flags themselves (has_tls / has_http / has_dns) are network-specific.
function _flagFor(kw) {
  if (kw === 'tls' || kw === 'sni' || kw === 'cipher' || kw === 'ja3' || kw === 'ja4') return 'has_tls';
  if (kw === 'http') return 'has_http';
  if (kw === 'dns')  return 'has_dns';
  return null;
}

// Workspace-owned data lifecycle. useCaptureData dispatches mount /
// bucket-change / time-range-change events here so core never hardcodes
// network endpoints. A workspace that omits a hook simply skips that effect.
const dataHooks = {
  // Called once after WorkspaceProvider mounts. Returns a partial state patch.
  onMount: async () => {
    const data = await fetchEdgeFieldMeta();
    if (!data?.fields?.length) return null;
    const seen = new Set();
    const hints = [];
    for (const f of data.fields) {
      for (const kw of (f.hint_keyword || [])) {
        const flag = _flagFor(kw);
        if (!flag) continue;
        const key = flag + ':' + kw;
        if (seen.has(key)) continue;
        seen.add(key);
        hints.push({ flag, keyword: kw });
      }
    }
    return hints.length ? { edgeFieldHints: hints } : null;
  },

  // Called when the timeline bucket size changes. Returns { timeline }.
  onBucketSecChange: async (bucketSec) => {
    const d = await fetchTimeline(bucketSec);
    return { timeline: d.buckets };
  },

  // Called when the debounced time range changes. Returns { sessions, sessionTotal, stats }.
  onTimeRangeChange: async (ts, te) => {
    const trParams = ts != null && te != null ? { timeStart: ts, timeEnd: te } : {};
    const [sessionData, statsData] = await Promise.all([
      fetchSessions(SESSIONS_FETCH_LIMIT, '', trParams),
      fetchStats(trParams),
    ]);
    return {
      sessions: sessionData.sessions || [],
      sessionTotal: sessionData.total ?? sessionData.sessions?.length ?? 0,
      stats: statsData.stats || {},
    };
  },
};

// Workspace-owned full-capture load. Phase 5.6 (B3) moves the 9-fetcher
// fan-out + protocol composite-key seed out of core's useCaptureLoad. The
// result shape is what onCaptureLoaded consumes in useCapture.
async function loadAll() {
  const [sd, td, pd, ss, pr, ps, an, sy, al] = await Promise.all([
    fetchStats(), fetchTimeline(), fetchProtocols(),
    fetchSessions(), fetchPluginResults(), fetchPluginSlots(),
    fetchAnnotations(), fetchSynthetic(), fetchAlerts(),
  ]);

  const sp = sd.stats?.protocols || {};
  const initKeys = [];
  const nonIpTransports = new Set(['ARP', 'OTHER']);
  for (const pName of pd.protocols) {
    if (!pName || !pName.trim()) continue;
    const info = sp[pName] || {};
    const transport = info.transport || pName;
    const v4 = info.ipv4 || 0;
    const v6 = info.ipv6 || 0;
    const total = info.packets || 0;
    if (nonIpTransports.has(transport)) {
      initKeys.push(`0/${transport}/${pName}`);
    } else {
      if (v4 > 0 || (v6 === 0 && total > 0)) initKeys.push(`4/${transport}/${pName}`);
      if (v6 > 0) initKeys.push(`6/${transport}/${pName}`);
    }
  }

  return {
    stats: sd.stats,
    timeline: td.buckets,
    timelineLength: td.buckets.length,
    protocols: pd.protocols,
    pColors: pd.colors,
    sessions: ss.sessions || [],
    fullSessions: ss.sessions || [],
    sessionTotal: ss.total ?? ss.sessions?.length ?? 0,
    pluginResults: pr.results || {},
    pluginSlots: ps.ui_slots || [],
    annotations: an.annotations || [],
    synthetic: sy.synthetic || [],
    alerts: al || { alerts: [], summary: {} },
    enabledProtocolKeys: initKeys,
  };
}

function enrichEdge(edge, srcNode, dstNode) {
  const srcIp = srcNode?.ips?.[0];
  const dstIp = dstNode?.ips?.[0];
  const endpointIps = [srcIp, dstIp].filter(Boolean);
  return {
    _srcIp: srcIp,
    _dstIp: dstIp,
    _endpointIps: endpointIps,
  };
}

const filterSuggestions = [
  'http', 'https', 'dns', 'tcp', 'udp', 'ssh', 'tls', 'arp',
  'icmp', 'ftp', 'smtp', 'smb', 'rdp', 'ntp', 'dhcp', 'quic',
  'quic.sni',
];

const filterExamples = [
  { label: 'IP address',    expr: 'ip == 10.0.0.1' },
  { label: 'CIDR subnet',   expr: 'ip == 192.168.1.0/24' },
  { label: 'Source IP',     expr: 'ip.src == 10.0.0.1' },
  { label: 'Protocol',      expr: 'http' },
  { label: 'Port',          expr: 'port == 443' },
  { label: 'Large traffic', expr: 'bytes > 100000' },
  { label: 'TLS SNI',       expr: 'tls.sni contains "google"' },
  { label: 'DNS query',     expr: 'dns contains "cloudflare"' },
  { label: 'Private hosts', expr: 'private' },
  { label: 'Compound',      expr: 'http && ip.src == 192.168.1.0/24' },
  { label: 'OS filter',     expr: 'os contains "Linux"' },
];

// Graph Options catalog — declares the mode lists shown in the Graph Options
// panel + the field name on node/edge each weight mode reads. Phase 5.7 (B2)
// moves these out of `useCaptureFilters` defaults + GraphOptionsPanel hardcodes.
// Network preserves the historical four mode lists exactly. The
// `nodeColorModes` legendItems live in the existing static `graphLegendData`
// map keyed by mode id, so no per-mode legend declaration is required here.
const graphDisplay = {
  // `scale` controls how the raw field value maps to node radius: 'log' for
  // wide-range counters like bytes (default), 'sqrt' for narrower counters
  // like packets. Edges always scale linearly against the max edge metric.
  nodeWeightModes: [
    { id: 'bytes',   label: 'Bytes',   field: 'total_bytes',  scale: 'log'  },
    { id: 'packets', label: 'Packets', field: 'packet_count', scale: 'sqrt' },
  ],
  edgeWeightModes: [
    { id: 'bytes',    label: 'Bytes',    field: 'total_bytes' },
    { id: 'packets',  label: 'Packets',  field: 'packet_count' },
    { id: 'sessions', label: 'Sessions', field: 'session_count' },
  ],
  nodeColorModes: [
    { id: 'address',  label: 'Address',  icon: '🌐', hint: 'Private vs external' },
    { id: 'os',       label: 'OS',       icon: '💻', hint: 'Detected OS family' },
    { id: 'protocol', label: 'Protocol', icon: '📡', hint: 'Dominant protocol' },
    { id: 'volume',   label: 'Volume',   icon: '🔥', hint: 'Bytes transferred' },
    { id: 'custom',   label: 'Custom',   icon: '🎨', hint: 'Your own IP rules', supportsCustomRules: true },
  ],
  edgeColorModes: [
    { id: 'protocol', label: 'Protocol', icon: '📡', hint: 'Per-protocol color' },
    { id: 'volume',   label: 'Volume',   icon: '🔥', hint: 'Bytes transferred' },
    { id: 'sessions', label: 'Sessions', icon: '🔗', hint: 'Session count' },
    { id: 'custom',   label: 'Custom',   icon: '🎨', hint: 'Your own rules', supportsCustomRules: true },
  ],
  defaults: {
    nodeWeight: 'bytes',
    edgeWeight: 'bytes',
    nodeColor:  'address',
    edgeColor:  'protocol',
  },
};

const networkWorkspace = {
  name: 'network',
  label: 'Network',
  enrichEdge,
  filterSuggestions,
  filterExamples,
  NodeDetail,
  EdgeDetail,
  FilterBar,
  UploadScreen,
  // Workspace-owned full-capture load (see useCaptureLoad)
  loadAll,
  // Workspace-owned data lifecycle (see useCaptureData)
  dataHooks,
  // Drop-zone accept list (see useCaptureLoad.handleDrop)
  acceptedExtensions: ['.pcap', '.pcapng', '.cap', '.log', '.csv'],
  // Search-effect helper for matching sessions onto edges (used when
  // a session row matches the search query). Forensic has no sessions
  // and omits this — useCaptureData skips the matcher when undefined.
  matchSessionToEdge,
  // Graph Options catalog (mode lists + defaults). See declaration above.
  graphDisplay,

  // Which sections to show in GraphOptionsPanel. Network shows all.
  graphOptions: { showData: true, showClustering: true },

  // Search bar placeholder text.
  searchPlaceholder: 'Search — IPs, MACs, hostnames, JA3, TLS, DNS…',
};

export default networkWorkspace;
