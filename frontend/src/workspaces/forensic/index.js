/**
 * Forensic workspace descriptor — Phase 5 / 5.5.
 *
 * Supplies workspace-specific hooks to the core engine:
 *   uploadFile      — calls /api/forensic/upload (used by useCaptureLoad)
 *   fetchStatus     — calls /api/forensic/status (used by useCaptureLoad on mount)
 *   loadAll         — fetches forensic graph + status after upload; returns the
 *                     shape onCaptureLoaded expects (stats.event_count included)
 *   fetchGraph      — called by useCaptureData E7 instead of the default fetchGraph
 *
 * Phase 5.5 descriptor additions:
 *   getTopBarStats  — returns [{value, label}] for the top bar stats strip
 *   supportedTabs   — array of left-panel tab keys to show (others hidden)
 *   LeftPanelTop    — replaces the protocol list in LeftPanel
 *   showTimeline    — false: hides the timeline strip (forensic has no timeline)
 *
 * NodeDetail / EdgeDetail / UploadScreen replace the generic/empty Phase 3 stubs.
 */

import NodeDetail from './NodeDetail';
import EdgeDetail from './EdgeDetail';
import UploadScreen from './UploadScreen';
import ArtifactBrowser from './ArtifactBrowser';
import ForensicStatsPanel from './StatsPanel';
import {
  uploadForensicEvtx,
  fetchForensicStatus,
  fetchForensicGraph,
  fetchForensicPlugins,
} from '@core/api';

// Schema-driven legend builders. Forensic colours nodes/edges from
// `workspace.schema.{node,edge}_types[*].color` (the aggregator stamps
// `node.color` / `edge.color`); the legend mirrors that mapping. Called by
// GraphLegend / GraphOptionsPanel with the live workspace (schema is loaded
// from the API at provider mount, so by the time these run it is present).
function _nodeLegendFromSchema(ws) {
  return (ws?.schema?.node_types || []).map(nt => ({
    label:  nt.label || nt.name,
    fill:   (nt.color || '#4fc3f7') + '22',
    stroke: nt.color || '#4fc3f7',
  }));
}
function _edgeLegendFromSchema(ws) {
  return (ws?.schema?.edge_types || []).map(et => ({
    label: et.label || et.name,
    fill:  et.color || '#8b949e',
  }));
}

// Graph Options catalog — see `network/index.js` for the full contract.
// Forensic data has no bytes/packets/sessions, so weight modes are
// event-density-shaped. Both colour modes always defer to schema colour
// (set by the aggregator on `node.color` / `edge.color`); mode IDs are
// declarative only — `resolveNodeColor` / `resolveEdgeColor` short-circuit
// on the stamped colour before consulting the mode.
const graphDisplay = {
  nodeWeightModes: [
    // sqrt scaling — event counts are typically smaller than byte counts;
    // sqrt distinguishes 5-vs-50 events better than log compresses them.
    { id: 'event_count',      label: 'Events',      field: 'event_count',      scale: 'sqrt' },
    { id: 'connection_count', label: 'Connections', field: 'connection_count', scale: 'sqrt' },
    { id: 'child_count',      label: 'Children',    field: 'child_count',      scale: 'sqrt' },
  ],
  edgeWeightModes: [
    { id: 'event_count', label: 'Events', field: 'event_count', scale: 'sqrt' },
  ],
  nodeColorModes: [
    { id: 'entity_type', label: 'Entity', icon: '●', hint: 'Schema colour per entity',
      legendItems: _nodeLegendFromSchema },
  ],
  edgeColorModes: [
    { id: 'action_type', label: 'Action', icon: '⚡', hint: 'Schema colour per action',
      legendItems: _edgeLegendFromSchema },
  ],
  defaults: {
    nodeWeight: 'event_count',
    edgeWeight: 'event_count',
    nodeColor:  'entity_type',
    edgeColor:  'action_type',
  },
};

function fN(n) {
  if (n == null) return '0';
  return n >= 1e6 ? (n / 1e6).toFixed(1) + 'M'
    : n >= 1e3 ? (n / 1e3).toFixed(1) + 'K'
    : String(n);
}

async function loadAll() {
  const [d, status, plugins] = await Promise.all([
    fetchForensicGraph(),
    fetchForensicStatus(),
    fetchForensicPlugins().catch(() => ({ results: {} })),
  ]);
  return {
    nodes: d.nodes || [],
    edges: d.edges || [],
    stats: { event_count: d.event_count ?? status.event_count ?? 0 },
    timeline: [],
    timelineLength: 0,
    protocols: [],
    pColors: {},
    sessions: [],
    fullSessions: [],
    sessionTotal: 0,
    pluginResults: plugins.results || {},
    pluginSlots: plugins.slots || [],
    annotations: [],
    synthetic: [],
    alerts: { alerts: [], summary: {} },
    enabledProtocolKeys: [],
  };
}

const forensicWorkspace = {
  name: 'forensic',
  label: 'Forensic',

  // Upload + status hooks consumed by useCaptureLoad
  uploadFile:  uploadForensicEvtx,
  fetchStatus: fetchForensicStatus,
  loadAll,

  // Graph hook consumed by useCaptureData E7
  fetchGraph:  fetchForensicGraph,

  // Phase 5.5: workspace switcher descriptor fields
  showTimeline: false,

  // Forensic has no time-range / bucket / mount lifecycle — useCaptureData
  // skips its E0 / E3 / E4+E5 effects entirely when these are absent.
  dataHooks: {},

  // Drop-zone accept list (see useCaptureLoad.handleDrop)
  acceptedExtensions: ['.evtx', '.zip', '.csv'],

  // Per-event action_type (carried on each edge.events entry) maps to one of
  // the edge types in schema. EdgeDetail uses this to colour action badges
  // from the schema instead of redeclaring colours.
  actionTypeToEdgeType: {
    process_create:  'spawned',
    network_connect: 'connected',
    file_create:     'wrote',
    registry_set:    'set_value',
  },

  supportedTabs: [
    'stats', 'alerts', 'investigation', 'visualize',
    'graph-options', 'research', 'logs', 'help',
  ],

  // Research tab wiring: points ResearchPage at the forensic chart API.
  // hasCustomChart: false hides the network-specific custom chart builder.
  research: {
    apiBase: '/api/forensic/research',
    hasCustomChart: false,
  },

  // Top bar stats: events + artifact node count.
  // nodeCount is passed by App.jsx as c.visibleNodes.length.
  getTopBarStats: (stats, nodeCount) => [
    { value: fN(stats?.event_count ?? 0), label: 'events' },
    { value: nodeCount, label: 'artifacts' },
  ],

  // Replaces the protocol list in LeftPanel when forensic is active.
  LeftPanelTop: ArtifactBrowser,

  // UI components
  UploadScreen,
  NodeDetail,
  EdgeDetail,
  OverviewPanel: ForensicStatsPanel,

  // Graph Options catalog (mode lists + defaults). See declaration above.
  graphDisplay,
};

export default forensicWorkspace;
