/**
 * WorkspaceProvider — active-workspace context.
 *
 * On mount:
 *   1. Fetches `/api/workspace/current` → `{active, available}`.
 *   2. If `active` is null, renders `<WorkspaceSelector>` (Phase 3 landing).
 *   3. If set, picks the descriptor for that workspace, fetches
 *      `/api/workspace/schema`, and exposes `{...descriptor, schema}`
 *      through context.
 *
 * Descriptor selection is a static map (`network` / `forensic`) rather
 * than dynamic import — both bundles are tiny and eager loading avoids
 * a second Suspense boundary at the root.
 *
 * Phase 3 does not offer runtime switching: once a workspace is picked,
 * it is sticky via `backend/settings.json`. Changing it means editing
 * that file; the selector only appears when no selection exists.
 */

import React, { createContext, useContext, useCallback, useEffect, useMemo, useState } from 'react';
import networkWorkspace from '@workspaces/network';
import forensicWorkspace from '@workspaces/forensic';
import { getCurrentWorkspace, getWorkspaceSchema, selectWorkspace } from '@core/api';
import WorkspaceSelector from './WorkspaceSelector';

const DESCRIPTORS = {
  network: networkWorkspace,
  forensic: forensicWorkspace,
};

const WorkspaceContext = createContext(null);

export function WorkspaceProvider({ children }) {
  const [current, setCurrent] = useState(null);   // {active, available} | null
  const [schema, setSchema] = useState(null);
  const [error, setError] = useState(null);

  // Step 1: always fetch current first.
  useEffect(() => {
    let cancelled = false;
    getCurrentWorkspace()
      .then(c => { if (!cancelled) setCurrent(c); })
      .catch(e => { if (!cancelled) setError(e); });
    return () => { cancelled = true; };
  }, []);

  // Step 2: once current is known and active is non-null, fetch schema.
  useEffect(() => {
    if (!current?.active) return;
    let cancelled = false;
    getWorkspaceSchema()
      .then(s => { if (!cancelled) setSchema(s); })
      .catch(e => { if (!cancelled) setError(e); });
    return () => { cancelled = true; };
  }, [current?.active]);

  const switchWorkspace = useCallback(async (name) => {
    await selectWorkspace(name);
    setSchema(null);
    setCurrent(c => ({ ...c, active: name }));
  }, []);

  const value = useMemo(() => {
    if (!current?.active || !schema) return null;
    const desc = DESCRIPTORS[current.active];
    if (!desc) return null;
    return { ...desc, schema, available: current.available || [], switchWorkspace };
  }, [current?.active, current?.available, schema, switchWorkspace]);

  if (error) {
    return (
      <div style={{ padding: 24, color: 'var(--acR, #f85149)', fontFamily: 'var(--fn)' }}>
        Failed to load workspace: {String(error.message || error)}
      </div>
    );
  }

  if (!current) return null;                                // still fetching /current
  if (!current.active) {                                    // user hasn't picked
    return <WorkspaceSelector available={current.available} onSwitch={switchWorkspace} />;
  }
  if (!value) return null;                                  // schema in flight

  return (
    <WorkspaceContext.Provider value={value}>
      <React.Fragment key={current.active}>
        {children}
      </React.Fragment>
    </WorkspaceContext.Provider>
  );
}

export function useWorkspace() {
  const ws = useContext(WorkspaceContext);
  if (!ws) throw new Error('useWorkspace must be called inside <WorkspaceProvider>');
  return ws;
}
