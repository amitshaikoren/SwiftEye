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
import {
  uploadForensicEvtx,
  fetchForensicStatus,
  fetchForensicGraph,
} from '@core/api';

function fN(n) {
  if (n == null) return '0';
  return n >= 1e6 ? (n / 1e6).toFixed(1) + 'M'
    : n >= 1e3 ? (n / 1e3).toFixed(1) + 'K'
    : String(n);
}

async function loadAll() {
  const [d, status] = await Promise.all([fetchForensicGraph(), fetchForensicStatus()]);
  // Return the shape onCaptureLoaded expects.
  // stats.event_count is surfaced in the top bar via getTopBarStats.
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
    pluginResults: {},
    pluginSlots: [],
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
  acceptedExtensions: ['.evtx'],

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
    'graph-options', 'logs', 'help',
  ],

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
};

export default forensicWorkspace;
