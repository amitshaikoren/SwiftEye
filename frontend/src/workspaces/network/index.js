/**
 * Network workspace — registration object.
 *
 * `enrichEdge(edge, srcNode, dstNode)` returns extra synthetic wire keys
 * that the schema declares on flow edges (`_srcIp`, `_dstIp`,
 * `_endpointIps`). Core's display-filter pass calls this during edge
 * enrichment — keeping all "flow endpoint = host IP" knowledge inside the
 * network workspace so `core/` stays network-agnostic.
 *
 * `filterSuggestions` extends FilterBar autocomplete with protocol
 * shorthand (http, https, dns, tcp, …). `filterExamples` are the
 * example expressions shown in the filter-help popover. Both are
 * workspace-specific copy, declared here so FilterBar doesn't hardcode.
 *
 * `NodeDetail` / `EdgeDetail` are the right-panel components for a
 * single-host / single-flow selection. Core's `AppRightPanel` pulls
 * them off the descriptor so `core/` carries no hardcoded reference
 * to the network panels. Panel internals stay network-specific (Q3
 * sign-off: shallow refactor for phase 2 — full schema-driven node-
 * detail contract is deferred to `node-detail-contract.md`).
 */

import NodeDetail from './NodeDetail';
import EdgeDetail from './EdgeDetail';

function enrichEdge(edge, srcNode, dstNode) {
  const srcIp = srcNode?.ips?.[0];
  const dstIp = dstNode?.ips?.[0];
  const endpointIps = [srcIp, dstIp].filter(Boolean);
  return {
    _srcIp: srcIp,
    _dstIp: dstIp,
    _endpointIps: endpointIps,
  };
}

const filterSuggestions = [
  'http', 'https', 'dns', 'tcp', 'udp', 'ssh', 'tls', 'arp',
  'icmp', 'ftp', 'smtp', 'smb', 'rdp', 'ntp', 'dhcp', 'quic',
  'quic.sni',
];

const filterExamples = [
  { label: 'IP address',    expr: 'ip == 10.0.0.1' },
  { label: 'CIDR subnet',   expr: 'ip == 192.168.1.0/24' },
  { label: 'Source IP',     expr: 'ip.src == 10.0.0.1' },
  { label: 'Protocol',      expr: 'http' },
  { label: 'Port',          expr: 'port == 443' },
  { label: 'Large traffic', expr: 'bytes > 100000' },
  { label: 'TLS SNI',       expr: 'tls.sni contains "google"' },
  { label: 'DNS query',     expr: 'dns contains "cloudflare"' },
  { label: 'Private hosts', expr: 'private' },
  { label: 'Compound',      expr: 'http && ip.src == 192.168.1.0/24' },
  { label: 'OS filter',     expr: 'os contains "Linux"' },
];

const networkWorkspace = {
  name: 'network',
  label: 'Network',
  enrichEdge,
  filterSuggestions,
  filterExamples,
  NodeDetail,
  EdgeDetail,
};

export default networkWorkspace;
