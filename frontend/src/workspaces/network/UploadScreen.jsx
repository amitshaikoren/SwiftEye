/**
 * Network workspace — pre-capture / upload screen.
 *
 * Renders either the drop-zone or the Visualize page. Exposed through
 * the network workspace descriptor as `UploadScreen`; core's `App.jsx`
 * reads `useWorkspace().UploadScreen` for the unloaded state, so this
 * file owns all pcap/Zeek/tshark copy and extensions in one place.
 *
 * Props: visualize, loading, loadMsg, handleDrop, handleFileInput, error,
 *        switchPanel, schemaNegotiation, handleSchemaConfirm, handleSchemaCancel,
 *        schemaConfirming, typePicker, handleTypePickerConfirm, handleTypePickerCancel
 */

import React from 'react';
import logoFullData from '@/logoFullData';
import VisualizePage from '@core/components/VisualizePage';
import SchemaDialog from '@core/components/SchemaDialog';
import TypePickerDialog from '@core/components/TypePickerDialog';

export default function NetworkUploadScreen({
  visualize,
  loading, loadMsg,
  handleDrop, handleFileInput, error,
  switchPanel,
  schemaNegotiation, handleSchemaConfirm, handleSchemaCancel, schemaConfirming,
  typePicker, handleTypePickerConfirm, handleTypePickerCancel,
}) {
  if (visualize) {
    return (
      <div style={{ height: '100vh', display: 'flex', flexDirection: 'column', overflow: 'hidden', background: 'var(--bg)' }}>
        <div style={{ padding: '8px 16px', borderBottom: '1px solid var(--bd)', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          <button className="btn" onClick={() => switchPanel('stats')}
            style={{ fontSize: 10, padding: '3px 10px' }}>← Back to upload</button>
          <span style={{ fontSize: 12, color: 'var(--txD)' }}>No capture loaded — Visualize mode only</span>
        </div>
        <VisualizePage />
      </div>
    );
  }

  return (
    <div style={{ width: '100%', height: '100vh', background: 'var(--bg)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      {loading ? (
        <div style={{ textAlign: 'center' }}>
          <div style={{ width: 40, height: 40, border: '3px solid var(--bd)', borderTopColor: 'var(--ac)', borderRadius: '50%', animation: 'spin 0.8s linear infinite', margin: '0 auto 16px' }} />
          <div style={{ color: 'var(--txM)', fontSize: 13 }}>{loadMsg}</div>
        </div>
      ) : (
        <div
          onDrop={handleDrop} onDragOver={e => e.preventDefault()}
          onClick={() => document.getElementById('pcap-up').click()}
          style={{
            textAlign: 'center', padding: '64px 80px',
            border: '1.5px dashed rgba(88,166,255,.3)', borderRadius: 20,
            cursor: 'pointer', minWidth: 460,
            background: 'rgba(88,166,255,.02)',
          }}
        >
          <img src={logoFullData} alt="SwiftEye" style={{ height: 120, marginBottom: 40, opacity: 0.95 }} />
          <div style={{
            width: 64, height: 64, margin: '0 auto 24px', borderRadius: 16,
            background: 'rgba(88,166,255,.08)', border: '1px solid rgba(88,166,255,.25)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--ac)" strokeWidth="1.5">
              <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12" />
            </svg>
          </div>
          <div style={{ fontSize: 16, color: 'var(--txM)', marginBottom: 10 }}>
            Drop <span style={{ color: 'var(--ac)' }}>capture files</span> here <span style={{ fontSize: 10, color: 'var(--txD)' }}>(pcap, Zeek logs, tshark CSV)</span>
          </div>
          <div style={{ fontSize: 12, color: 'var(--txD)' }}>or click to browse · multiple files merge by timestamp · max 500MB each</div>
          {error && <div style={{ marginTop: 20, color: 'var(--acR)', fontSize: 13 }}>{error}</div>}
          <input id="pcap-up" type="file" accept=".pcap,.pcapng,.cap,.log,.csv,.parquet" multiple onChange={handleFileInput} style={{ display: 'none' }} />
        </div>
      )}
      <div style={{ position: 'absolute', bottom: 24, display: 'flex', gap: 12 }}>
        <button className="btn" onClick={e => { e.stopPropagation(); switchPanel('visualize'); }}
          style={{ fontSize: 11, padding: '6px 16px', opacity: 0.7 }}>
          📂 Visualize custom data
        </button>
      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
      {schemaNegotiation && (
        <SchemaDialog
          report={schemaNegotiation.report}
          stagingToken={schemaNegotiation.stagingToken}
          fileName={schemaNegotiation.fileName}
          onConfirm={handleSchemaConfirm}
          onCancel={handleSchemaCancel}
          loading={schemaConfirming}
        />
      )}
      {typePicker && (
        <TypePickerDialog
          fileName={typePicker.files[0]?.name || 'file'}
          availableAdapters={typePicker.availableAdapters}
          onConfirm={handleTypePickerConfirm}
          onCancel={handleTypePickerCancel}
        />
      )}
    </div>
  );
}
