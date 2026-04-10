/**
 * useAnnotationsAndSynthetic — annotations, synthetic elements, and alerts.
 *
 * Extracted from useCapture as part of the decomposition (v0.25.0).
 * Lowest-coupling slice: only cross-slice dependency is setGraph (via ref)
 * for synthetic node/edge mutations.
 */

import { useState, useCallback } from 'react';
import {
  createAnnotation, updateAnnotation, deleteAnnotation,
  createSynthetic, updateSynthetic, deleteSynthetic,
} from '../api';

export function useAnnotationsAndSynthetic({ setGraphRef }) {
  const [annotations, setAnnotations] = useState([]);
  const [synthetic, setSynthetic]     = useState([]);
  const [alerts, setAlerts]           = useState({ alerts: [], summary: {} });

  // ── Init from full-capture load ──────────────────────────────────

  const initFromLoad = useCallback(({ annotations: a, synthetic: s, alerts: al }) => {
    setAnnotations(a || []);
    setSynthetic(s || []);
    setAlerts(al || { alerts: [], summary: {} });
  }, []);

  // ── Annotations CRUD ─────────────────────────────────────────────

  async function handleAddAnnotation(x, y) {
    const id = crypto.randomUUID();
    const ann = { id, x, y, label: 'Note', color: '#f0883e' };
    setAnnotations(prev => [...prev, ann]);
    try { await createAnnotation(ann); } catch (e) { console.error(e); }
  }

  async function handleUpdateAnnotation(id, updates) {
    setAnnotations(prev => prev.map(a => a.id === id ? { ...a, ...updates } : a));
    try { await updateAnnotation(id, updates); } catch (e) { console.error(e); }
  }

  async function handleDeleteAnnotation(id) {
    setAnnotations(prev => prev.filter(a => a.id !== id));
    try { await deleteAnnotation(id); } catch (e) { console.error(e); }
  }

  async function handleAddNodeAnnotation(nodeId, nodeLabel) {
    const id = crypto.randomUUID();
    const ann = { id, x: 0, y: 0, label: nodeLabel || 'Note', color: '#58a6ff', node_id: nodeId };
    setAnnotations(prev => [...prev, ann]);
    try { await createAnnotation(ann); } catch (e) { console.error(e); }
  }

  async function handleAddEdgeAnnotation(edgeId) {
    const id = crypto.randomUUID();
    const ann = { id, x: 0, y: 0, label: 'Note', color: '#bc8cff', edge_id: edgeId };
    setAnnotations(prev => [...prev, ann]);
    try { await createAnnotation(ann); } catch (e) { console.error(e); }
  }

  // ── Synthetic elements ───────────────────────────────────────────

  async function handleAddSyntheticNode(nodeData) {
    const id = crypto.randomUUID();
    const obj = {
      ...nodeData, id, type: 'node', synthetic: true,
      ips: nodeData.ip ? [nodeData.ip] : [id],
      macs: [], protocols: [], hostnames: [],
      total_bytes: 0, packet_count: 0,
      is_private: false, is_subnet: false,
      ttls_out: [], ttls_in: [],
    };
    setSynthetic(prev => [...prev, obj]);
    setGraphRef.current(prev => ({ ...prev, nodes: [...(prev.nodes || []), obj] }));
    try { await createSynthetic(obj); } catch (e) { console.error(e); }
  }

  async function handleAddSyntheticEdge(edgeData) {
    const id = crypto.randomUUID();
    const obj = {
      ...edgeData, id, type: 'edge', synthetic: true,
      total_bytes: 0, packet_count: 0,
      ports: [], tls_snis: [], tls_versions: [], tls_ciphers: [],
      tls_selected_ciphers: [], http_hosts: [], dns_queries: [],
      ja3_hashes: [], ja4_hashes: [],
    };
    setSynthetic(prev => [...prev, obj]);
    setGraphRef.current(prev => ({ ...prev, edges: [...(prev.edges || []), obj] }));
    try { await createSynthetic(obj); } catch (e) { console.error(e); }
  }

  async function handleDeleteSynthetic(id) {
    setSynthetic(prev => prev.filter(s => s.id !== id));
    setGraphRef.current(prev => ({
      nodes: (prev.nodes || []).filter(n => n.id !== id),
      edges: (prev.edges || []).filter(e => e.id !== id),
    }));
    try { await deleteSynthetic(id); } catch (e) { console.error(e); }
  }

  async function handleUpdateSyntheticNode(id, updates) {
    setGraphRef.current(prev => ({
      ...prev,
      nodes: (prev.nodes || []).map(n => n.id === id ? { ...n, ...updates } : n),
    }));
    setSynthetic(prev => prev.map(s => s.id === id ? { ...s, ...updates } : s));
    try { await updateSynthetic(id, updates); } catch (e) { console.error(e); }
  }

  async function handleSaveNote(targetId, text, existingId, targetType = 'node_id') {
    const id = existingId || crypto.randomUUID();
    const ann = { id, annotation_type: 'note', [targetType]: targetId, label: '', text, x: 0, y: 0 };
    if (existingId) {
      setAnnotations(prev => prev.map(a => a.id === id ? { ...a, text } : a));
      try { await updateAnnotation(id, { text }); } catch (e) { console.error(e); }
    } else {
      setAnnotations(prev => [...prev, ann]);
      try { await createAnnotation(ann); } catch (e) { console.error(e); }
    }
  }

  return {
    annotations, synthetic, alerts, setAlerts,
    initFromLoad,
    handleAddAnnotation, handleUpdateAnnotation, handleDeleteAnnotation,
    handleAddNodeAnnotation, handleAddEdgeAnnotation,
    handleAddSyntheticNode, handleAddSyntheticEdge, handleDeleteSynthetic,
    handleUpdateSyntheticNode, handleSaveNote,
  };
}
