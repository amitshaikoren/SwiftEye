"""
Pure session↔edge matching helpers.

Shared between data.aggregator (build_analysis_graph) and storage.memory
(MemoryBackend.get_sessions_for_edge). No storage state — safe to import
from either layer.
"""

from ipaddress import IPv4Network, IPv4Address


def _ip_matches_endpoint(ip: str, endpoint: str) -> bool:
    """Check if a raw IP matches an edge endpoint.

    Handles:
      - Direct IP match ("10.0.0.1" == "10.0.0.1")
      - Subnet CIDR ("10.0.0.1" in "10.0.0.0/24")
      - MAC-split node IDs ("10.0.0.1::aa:bb:cc" → compare "10.0.0.1")
    """
    if ip == endpoint:
        return True
    # MAC-split: "10.0.0.1::aa:bb:cc:dd:ee:ff" → strip MAC suffix
    if "::" in endpoint and not endpoint.startswith("::"):
        base_ip = endpoint.split("::")[0]
        if ip == base_ip:
            return True
    # Subnet CIDR: "192.168.1.0/24"
    if "/" in endpoint and ":" not in ip:
        try:
            return IPv4Address(ip) in IPv4Network(endpoint, strict=False)
        except (ValueError, TypeError):
            pass
    return False


def _protocol_matches(session_protocol: str, session_transport: str,
                      edge_protocol: str) -> bool:
    """Check if a session's protocol matches an edge's protocol.

    Matches when:
      - session.protocol == edge_protocol (normal case, e.g. both "TLS")
      - session.transport == edge_protocol (session stayed as "TCP" but
        edge is "TCP" for handshake packets)
    """
    return session_protocol == edge_protocol or session_transport == edge_protocol


def _session_matches_edge(session: dict, edge_src: str, edge_dst: str,
                          edge_protocol: str) -> bool:
    """Canonical check: does this session belong to this edge?"""
    s_src = session.get("src_ip", "")
    s_dst = session.get("dst_ip", "")
    s_proto = session.get("protocol", "")
    s_transport = session.get("transport", "")

    if not _protocol_matches(s_proto, s_transport, edge_protocol):
        return False

    # Bidirectional IP match: session (src,dst) can be in either order
    # relative to edge (src,dst) because session IPs are sorted.
    return (
        (_ip_matches_endpoint(s_src, edge_src) and _ip_matches_endpoint(s_dst, edge_dst)) or
        (_ip_matches_endpoint(s_src, edge_dst) and _ip_matches_endpoint(s_dst, edge_src))
    )
