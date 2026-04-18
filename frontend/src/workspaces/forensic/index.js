/**
 * Forensic workspace — Phase 3 skeleton descriptor.
 *
 * Minimal surface. Phases 4–5 add `NodeDetail` / `EdgeDetail` (once
 * process/file/registry nodes exist), `FilterBar` (once the forensic
 * schema is populated with filterable fields), and any enrichment hooks
 * forensic edges need. Today the only concrete component is
 * `UploadScreen` — a placeholder so the unloaded forensic workspace
 * doesn't fall through to the network pcap-upload screen.
 *
 * Core components null-check the descriptor optional keys (FilterBar,
 * NodeDetail, EdgeDetail, enrichEdge) so an empty descriptor renders a
 * loaded-but-inactive workspace shell without crashing.
 */

import UploadScreen from './UploadScreen';

const forensicWorkspace = {
  name: 'forensic',
  label: 'Forensic',
  UploadScreen,
};

export default forensicWorkspace;
