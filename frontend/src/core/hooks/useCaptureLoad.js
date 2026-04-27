/**
 * useCaptureLoad — upload lifecycle state, schema negotiation, type picker,
 * flag modal, and the loadAll orchestrator.
 *
 * Extracted from useCapture as part of the decomposition (v0.25.0).
 * Created last in the implementation order because onCaptureLoaded depends
 * on setters from all other slices being in place.
 *
 * Cross-slice params:
 *   - loaded, setLoaded (from coordinator)
 *   - onCaptureLoaded(data) — callback that fans out to all slices
 *   - setGraph (from data slice — for handleMetadataInput)
 */

import { useState, useEffect, useCallback } from 'react';
import {
  fetchStatus, uploadPcap, uploadMetadata, confirmSchemaMapping,
} from '../api';
import { STORAGE_KEYS } from '../storageKeys';
import { useWorkspace } from '@/WorkspaceProvider';

export function useCaptureLoad({ loaded, setLoaded, onCaptureLoaded, setGraph }) {
  const workspace = useWorkspace();

  // ── Capture lifecycle state ──────────────────────────────────────

  const [loading, setLoading] = useState(false);
  const [loadMsg, setLoadMsg] = useState('');
  const [error, setError]     = useState('');
  const [fileName, setFileName] = useState('');
  const [sourceFiles, setSourceFiles] = useState([]);

  // ── Schema negotiation ───────────────────────────────────────────

  const [schemaNegotiation, setSchemaNegotiation] = useState(null);
  const [schemaConfirming, setSchemaConfirming] = useState(false);

  // ── Type picker ──────────────────────────────────────────────────

  const [typePicker, setTypePicker] = useState(null);

  // ── Flag modal ───────────────────────────────────────────────────

  const [flaggingTarget, setFlaggingTarget] = useState(null);
  function openFlagModal(entity_type, entity) {
    if (!entity || !entity_type) return;
    setFlaggingTarget({ entity, entity_type });
  }
  function closeFlagModal() { setFlaggingTarget(null); }

  // ── loadAll — dispatch to workspace, then fan out via callback ──
  //
  // Phase 5.6 (B3): the fetcher fan-out used to live here, hardcoded in
  // network shape. It now lives on the workspace descriptor; core only
  // owns workspace-agnostic concerns (scope-pill reset).

  const loadAll = useCallback(async () => {
    // Reset scope pills to SCOPED on every fresh capture load
    try {
      localStorage.removeItem(STORAGE_KEYS.SCOPE_NODE);
      localStorage.removeItem(STORAGE_KEYS.SCOPE_EDGE);
      Object.keys(localStorage)
        .filter(k => k.startsWith(STORAGE_KEYS.SCOPE_SLOT_PREFIX))
        .forEach(k => localStorage.removeItem(k));
    } catch {}

    if (!workspace.loadAll) {
      throw new Error(`Workspace "${workspace.name}" did not declare loadAll()`);
    }
    const data = await workspace.loadAll();
    onCaptureLoaded(data);
  }, [workspace, onCaptureLoaded]);

  // ── E1: mount — check if capture already loaded server-side ──────

  useEffect(() => {
    const statusFn = workspace.fetchStatus || fetchStatus;
    statusFn().then(d => {
      const isLoaded = d.capture_loaded ?? d.loaded;
      if (isLoaded) {
        setFileName(d.file_name);
        loadAll();
      }
    }).catch(() => {});
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Upload handlers ──────────────────────────────────────────────

  async function handleUpload(files, forceAdapter = null) {
    setLoading(true); setError(''); setLoadMsg('Uploading...');
    try {
      setLoadMsg('Parsing capture data...');

      // Workspace-provided upload overrides the default network upload.
      if (workspace.uploadFile) {
        const file = Array.isArray(files) ? files[0] : files;
        const res = await workspace.uploadFile(file);
        setFileName(res.file_name);
        setSourceFiles([res.file_name]);
        setLoadMsg('Building graph...');
        await loadAll();
        setLoading(false);
        return;
      }

      const res = await uploadPcap(files, forceAdapter);

      if (res.detection_failed) {
        setTypePicker({ files, availableAdapters: res.available_adapters || [] });
        setLoading(false);
        return;
      }

      if (res.schema_negotiation_required) {
        setSchemaNegotiation({
          stagingToken: res.staging_token,
          fileName: res.file_name,
          report: res.schema_report,
        });
        setLoading(false);
        return;
      }

      setFileName(res.file_name);
      setSourceFiles(res.source_files || [res.file_name]);
      setLoadMsg('Loading...');
      await loadAll();
      setLoading(false);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  }

  async function handleTypePickerConfirm(adapterName) {
    if (!typePicker) return;
    const { files } = typePicker;
    setTypePicker(null);
    await handleUpload(files, adapterName);
  }

  function handleTypePickerCancel() {
    setTypePicker(null);
  }

  async function handleSchemaConfirm(mapping) {
    if (!schemaNegotiation) return;
    setSchemaConfirming(true);
    try {
      const res = await confirmSchemaMapping(schemaNegotiation.stagingToken, mapping);
      setSchemaNegotiation(null);
      setFileName(res.file_name);
      setSourceFiles(res.source_files || [res.file_name]);
      setLoadMsg('Loading...');
      await loadAll();
    } catch (err) {
      setError(err.message);
    } finally {
      setSchemaConfirming(false);
    }
  }

  function handleSchemaCancel() {
    setSchemaNegotiation(null);
  }

  function handleDrop(e) {
    e.preventDefault();
    // Workspace declares which extensions its drop-zone accepts. Falls back to
    // the network defaults so a workspace that omits the field still works.
    const exts = workspace.acceptedExtensions || ['.pcap', '.pcapng', '.cap', '.log', '.csv'];
    const files = Array.from(e.dataTransfer.files).filter(f =>
      exts.some(ext => f.name.toLowerCase().endsWith(ext))
    );
    if (files.length) handleUpload(files);
  }

  function handleFileInput(e) {
    const files = Array.from(e.target.files || []);
    if (files.length) handleUpload(files);
    e.target.value = '';
  }

  async function handleMetadataInput(e) {
    const f = e.target.files?.[0];
    if (!f) return;
    try {
      await uploadMetadata(f);
      setGraph(prev => ({ ...prev })); // force graph re-fetch
    } catch (err) {
      console.error('Metadata upload failed:', err);
    }
    e.target.value = '';
  }

  return {
    loaded, loading, loadMsg, error, fileName, sourceFiles,
    handleUpload, handleDrop, handleFileInput, handleMetadataInput,
    schemaNegotiation, schemaConfirming, handleSchemaConfirm, handleSchemaCancel,
    typePicker, handleTypePickerConfirm, handleTypePickerCancel,
    flaggingTarget, openFlagModal, closeFlagModal,
  };
}
