/**
 * WorkspaceProvider — active-workspace context.
 *
 * Phase 1: exists but nothing consumes it yet. Default active workspace is
 * `network`. Phase 2 wires schema + detail panels through this provider so
 * core shells render workspace-specific content without hard-coded imports.
 */

import React, { createContext, useContext, useMemo } from 'react';
import networkWorkspace from './workspaces/network';

const WorkspaceContext = createContext(null);

export function WorkspaceProvider({ children }) {
  const value = useMemo(() => networkWorkspace, []);
  return (
    <WorkspaceContext.Provider value={value}>
      {children}
    </WorkspaceContext.Provider>
  );
}

export function useWorkspace() {
  const ws = useContext(WorkspaceContext);
  if (!ws) throw new Error('useWorkspace must be called inside <WorkspaceProvider>');
  return ws;
}
