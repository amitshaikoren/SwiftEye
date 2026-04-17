/**
 * Canonical session↔edge matching logic (client-side mirror).
 *
 * Mirrors backend storage.memory._session_matches_edge exactly.
 * Used by NodeDetail and useCapture search for fast in-memory matching.
 * EdgeDetail uses the /api/edge-sessions endpoint instead (unlimited).
 */

function ipInCidr(ip, cidr) {
  if (!cidr.includes('/')) return false;
  try {
    const [base, bits] = cidr.split('/');
    const mask = ~((1 << (32 - parseInt(bits, 10))) - 1) >>> 0;
    const toInt = s => s.split('.').reduce((a, b) => (a << 8) | parseInt(b, 10), 0) >>> 0;
    return (toInt(ip) & mask) === (toInt(base) & mask);
  } catch { return false; }
}

function ipMatchesEndpoint(ip, endpoint, nodeIpsMap) {
  if (ip === endpoint) return true;
  // Node IP set: endpoint is a node ID, check if session IP is one of its IPs
  if (nodeIpsMap) {
    const nodeIps = nodeIpsMap.get(endpoint);
    if (nodeIps && nodeIps.has(ip)) return true;
  }
  // MAC-split: "10.0.0.1::aa:bb:cc:dd:ee:ff"
  if (endpoint.includes('::') && !endpoint.startsWith('::')) {
    if (ip === endpoint.split('::')[0]) return true;
  }
  // Subnet CIDR
  if (endpoint.includes('/') && !ip.includes(':')) {
    if (ipInCidr(ip, endpoint)) return true;
  }
  return false;
}

function protocolMatches(sessionProtocol, sessionTransport, edgeProtocol) {
  return sessionProtocol === edgeProtocol || sessionTransport === edgeProtocol;
}

/**
 * Check if a session belongs to an edge.
 *
 * @param {object} session - Session object with src_ip, dst_ip, protocol, transport
 * @param {string} edgeSrc - Edge source node ID
 * @param {string} edgeDst - Edge target node ID
 * @param {string} edgeProtocol - Edge protocol
 * @param {Map} [nodeIpsMap] - Optional Map<nodeId, Set<ip>> for cluster/grouped nodes
 */
export function matchSessionToEdge(session, edgeSrc, edgeDst, edgeProtocol, nodeIpsMap) {
  const sSrc = session.src_ip || '';
  const sDst = session.dst_ip || '';
  const sProto = session.protocol || '';
  const sTrans = session.transport || '';

  if (!protocolMatches(sProto, sTrans, edgeProtocol)) return false;

  return (
    (ipMatchesEndpoint(sSrc, edgeSrc, nodeIpsMap) && ipMatchesEndpoint(sDst, edgeDst, nodeIpsMap)) ||
    (ipMatchesEndpoint(sSrc, edgeDst, nodeIpsMap) && ipMatchesEndpoint(sDst, edgeSrc, nodeIpsMap))
  );
}
