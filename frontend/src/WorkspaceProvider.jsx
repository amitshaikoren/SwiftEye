/**
 * WorkspaceProvider — active-workspace context.
 *
 * On mount, fetches the backend's `/api/workspace/schema` once and exposes
 * the merged descriptor (`{ ...networkWorkspace, schema }`) through context.
 * Consumers (displayFilter, FilterBar) dispatch on `schema.node_types` /
 * `schema.edge_types` rather than hardcoding field names. Renders `null`
 * until the schema resolves — fetch is one-shot at app load.
 */

import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import networkWorkspace from '@workspaces/network';
import { getWorkspaceSchema } from '@core/api';

const WorkspaceContext = createContext(null);

export function WorkspaceProvider({ children }) {
  const [schema, setSchema] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    getWorkspaceSchema()
      .then(s => { if (!cancelled) setSchema(s); })
      .catch(e => { if (!cancelled) setError(e); });
    return () => { cancelled = true; };
  }, []);

  const value = useMemo(
    () => (schema ? { ...networkWorkspace, schema } : null),
    [schema],
  );

  if (error) {
    return (
      <div style={{ padding: 24, color: 'var(--acR)', fontFamily: 'var(--fn)' }}>
        Failed to load workspace schema: {String(error.message || error)}
      </div>
    );
  }
  if (!value) return null;

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
