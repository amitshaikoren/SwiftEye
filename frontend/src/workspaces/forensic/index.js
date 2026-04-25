/**
 * Forensic workspace descriptor — Phase 5.
 *
 * Supplies workspace-specific hooks to the core engine:
 *   uploadFile   — calls /api/forensic/upload (used by useCaptureLoad)
 *   fetchStatus  — calls /api/forensic/status (used by useCaptureLoad on mount)
 *   loadAll      — fetches the forensic graph after upload; returns {nodes, edges}
 *                  wrapped in the shape onCaptureLoaded expects
 *   fetchGraph   — called by useCaptureData E7 instead of the default fetchGraph
 *
 * NodeDetail / EdgeDetail / UploadScreen replace the generic/empty Phase 3 stubs.
 */

import NodeDetail from './NodeDetail';
import EdgeDetail from './EdgeDetail';
import UploadScreen from './UploadScreen';
import {
  uploadForensicEvtx,
  fetchForensicStatus,
  fetchForensicGraph,
} from '@core/api';

async function loadAll() {
  const d = await fetchForensicGraph();
  // Return a shape compatible with onCaptureLoaded in useCapture.js.
  // Slices that expect network data (stats, sessions, etc.) receive empty/null
  // and their initial-state defaults ([], {}, 0) keep the UI stable.
  return {
    nodes: d.nodes || [],
    edges: d.edges || [],
    stats: null,
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

  // UI components
  UploadScreen,
  NodeDetail,
  EdgeDetail,
};

export default forensicWorkspace;
