/**
 * Network workspace — registration object.
 *
 * Phase 1: exposes a minimal descriptor. Phase 2 adds schema + detail-panel
 * component refs so WorkspaceProvider can hand them to core shells.
 */

const networkWorkspace = {
  name: 'network',
  label: 'Network (pcap)',
};

export default networkWorkspace;
