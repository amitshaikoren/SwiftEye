/**
 * Forensic workspace — node detail panel.
 *
 * Renders per-type field lists for process, file, registry, and endpoint
 * nodes from the forensic graph. Field order matches schema.py.
 *
 * Plugin sections (LOLbin, binary type, registry category) are rendered
 * below the static fields using pluginResults + uiSlots passed from
 * AppRightPanel. Each section uses Collapse + GenericDisplay so no
 * dedicated frontend renderer is needed.
 */

import React from 'react';
import Row from '../../core/components/Row';
import Collapse from '../../core/components/Collapse';
import { GenericDisplay } from '../../core/components/PluginSection';

// ── Per-type renderers ───────────────────────────────────────────────────────

function ProcessDetail({ node }) {
  return (
    <>
      {node.image         && <Row l="Image"           v={node.image} />}
      {node.command_line  && <Row l="Command Line"    v={node.command_line} />}
      {node.user          && <Row l="User"            v={node.user} />}
      {node.pid  != null  && <Row l="PID"             v={String(node.pid)} />}
      {node.guid          && <Row l="Process GUID"    v={node.guid} />}
      {node.hashes        && <Row l="Hashes"          v={node.hashes} />}
      {node.integrity_level && <Row l="Integrity"     v={node.integrity_level} />}
      {node.computer      && <Row l="Computer"        v={node.computer} />}
    </>
  );
}

function FileDetail({ node }) {
  return (
    <>
      {node.path      && <Row l="Path"      v={node.path} />}
      {node.extension && <Row l="Extension" v={node.extension} />}
    </>
  );
}

function RegistryDetail({ node }) {
  return (
    <>
      {node.key  && <Row l="Key"  v={node.key} />}
      {node.hive && <Row l="Hive" v={node.hive} />}
    </>
  );
}

function EndpointDetail({ node }) {
  return (
    <>
      {node.ip       && <Row l="IP"       v={node.ip} />}
      {node.port != null && <Row l="Port" v={String(node.port)} />}
      {node.hostname && <Row l="Hostname" v={node.hostname} />}
    </>
  );
}

// ── Plugin sections ───────────────────────────────────────────────────────────

function ForensicPluginSections({ nodeId, pluginResults, uiSlots }) {
  if (!pluginResults || !uiSlots || uiSlots.length === 0) return null;

  const nodeSlots = uiSlots
    .filter(s => s.slot_type === 'node_detail_section')
    .sort((a, b) => a.priority - b.priority);

  return nodeSlots.map(slot => {
    const nodeData = pluginResults?.[slot.plugin]?.[nodeId];
    if (!nodeData?._display || nodeData._display.length === 0) return null;
    return (
      <Collapse key={`${slot.plugin}.${slot.slot_id}`} title={slot.title} open={slot.default_open}>
        <GenericDisplay display={nodeData._display} />
      </Collapse>
    );
  });
}

// ── Type → color + label ─────────────────────────────────────────────────────

const TYPE_META = {
  process:  { color: '#4fc3f7', label: 'Process' },
  file:     { color: '#fff176', label: 'File' },
  registry: { color: '#ffb74d', label: 'Registry' },
  endpoint: { color: '#ce93d8', label: 'Endpoint' },
};

// ── Main component ────────────────────────────────────────────────────────────

export default function ForensicNodeDetail({ nodeId, nodes = [], onClear, pluginResults, uiSlots }) {
  const node = nodes.find(n => n.id === nodeId);
  if (!node) return null;

  const meta = TYPE_META[node.type] || { color: 'var(--ac)', label: node.type || 'Node' };

  return (
    <div style={{ fontFamily: 'var(--fn)', fontSize: 12, color: 'var(--tx)', padding: '10px 14px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
        <span style={{
          fontSize: 9, padding: '2px 7px', borderRadius: 8, fontWeight: 600,
          background: meta.color + '22', color: meta.color,
          border: '1px solid ' + meta.color + '44',
          textTransform: 'uppercase', letterSpacing: '0.06em',
        }}>
          {meta.label}
        </span>
        <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--txM)', fontSize: 12 }}>
          {node.label || node.id}
        </span>
        {onClear && (
          <button
            onClick={onClear}
            style={{ background: 'none', border: 'none', color: 'var(--txD)', cursor: 'pointer', fontSize: 14, lineHeight: 1, padding: 2 }}
          >×</button>
        )}
      </div>

      {/* Static fields */}
      {node.type === 'process'  && <ProcessDetail  node={node} />}
      {node.type === 'file'     && <FileDetail     node={node} />}
      {node.type === 'registry' && <RegistryDetail node={node} />}
      {node.type === 'endpoint' && <EndpointDetail node={node} />}

      {/* Plugin classifier sections */}
      <ForensicPluginSections nodeId={nodeId} pluginResults={pluginResults} uiSlots={uiSlots} />

      {/* Entity ID */}
      <div style={{ marginTop: 12, paddingTop: 8, borderTop: '1px solid var(--bd)' }}>
        <Row l="Entity ID" v={node.id} />
      </div>
    </div>
  );
}
