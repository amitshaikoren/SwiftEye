"""
Node Merger — Pre-aggregation Plugin

Merges IPs that represent the same physical host into a single canonical ID
before build_graph() runs. Returns an entity_map: Dict[str, str] that maps
every IP to its canonical representative IP.

Strategy: merge_by_mac
    IPs that share a MAC address are the same host. Common in captures that
    include ARP — the MAC ties the IPs together definitively.
    Canonical ID = most-seen IPv4 address, falling back to most-seen IPv6.

Note: a previous "merge_dual_stack" strategy that looked for IPv4/IPv6 pairs
in the same packet was removed — IPv4 and IPv6 cannot coexist in the same
packet header, so the strategy never matched anything real. MAC-based merging
already handles dual-stack hosts correctly when ARP/NDP traffic is present.
"""

import logging
from typing import Dict, List, Set
from collections import defaultdict

from workspaces.network.parser.packet import PacketRecord
from workspaces.network.parser.oui import lookup_vendor

logger = logging.getLogger("swifteye.node_merger")

# MAC OUI vendors that are purely network infrastructure — routers, switches,
# firewalls, APs. A MAC from one of these should never be used as a merge key
# because it's a forwarding device, not an end-host with multiple IP addresses.
# Conservative list: only vendors that make NO end-user computing devices.
_INFRA_VENDORS = {
    "Cisco", "Juniper", "Aruba", "Ubiquiti", "Palo Alto",
    "Fortinet", "Sophos", "WatchGuard", "Brocade", "Extreme",
    "Arista", "MikroTik", "Ruckus", "Meraki",
}


def _is_router_mac(mac: str) -> bool:
    """Return True if the MAC belongs to a known network infrastructure vendor."""
    vendor = lookup_vendor(mac)
    if not vendor:
        return False
    # Check for exact match or prefix match (e.g. "Cisco Systems" matches "Cisco")
    vendor_lower = vendor.lower()
    return any(infra.lower() in vendor_lower for infra in _INFRA_VENDORS)


def _is_mergeable(ip: str) -> bool:
    """
    Only merge unicast IPs. Excludes:
    - IPv6 multicast (ff00::/8)
    - IPv6 link-local (fe80::/10) — these are per-interface addresses that share
      a MAC with the host's global address. Merging them is technically correct
      but hides useful link-local traffic; leave them as separate nodes.
    - IPv4 multicast (224.0.0.0/4)
    - IPv4 broadcast (255.255.255.255)
    - Loopback (127.x.x.x, ::1)
    """
    if not ip:
        return False
    if ":" in ip:
        # IPv6
        lower = ip.lower()
        if lower.startswith("ff"):    return False  # multicast
        if lower.startswith("fe80"):  return False  # link-local
        if lower == "::1":            return False  # loopback
        return True
    else:
        # IPv4
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        first = int(parts[0]) if parts[0].isdigit() else 0
        if first >= 224:              return False  # multicast + broadcast
        if first == 127:              return False  # loopback
        return True


def _is_multicast_mac(mac: str) -> bool:
    """
    IPv6 multicast MACs are 33:33:xx:xx:xx:xx.
    IPv4 multicast MACs are 01:00:5e:xx:xx:xx.
    These should never be used as merge keys.
    """
    m = mac.lower()
    return m.startswith("33:33:") or m.startswith("01:00:5e:")


def build_entity_map(
    packets: List[PacketRecord],
    merge_by_mac: bool = True,
) -> Dict[str, str]:
    """
    Return an entity_map: { ip → canonical_ip }.

    All IPs map to themselves by default. Merged IPs map to their group's
    canonical representative. The aggregator applies this before building nodes.

    Args:
        packets:      raw packet list (pre-filter)
        merge_by_mac: merge IPs sharing a MAC address

    Returns:
        Dict mapping every seen IP to its canonical IP.
        IPs not merged map to themselves.
    """
    if not merge_by_mac:
        return {}

    ip_count:   Dict[str, int]      = defaultdict(int)
    mac_to_ips: Dict[str, Set[str]] = defaultdict(set)

    for pkt in packets:
        # CRITICAL: only use src_ip/src_mac pairs.
        # dst_mac is the next-hop MAC (usually the router/gateway), NOT the
        # destination host's MAC. Using dst_mac would merge all external IPs
        # that route through the same gateway into one node.
        ip, mac = pkt.src_ip, pkt.src_mac
        if not ip:
            continue
        ip_count[ip] += 1
        if (mac and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "")
                and _is_mergeable(ip) and not _is_multicast_mac(mac)
                and not _is_router_mac(mac)):
            mac_to_ips[mac].add(ip)

        # Count dst_ip for ip_count (needed for canonical selection)
        # but do NOT add dst_ip to mac_to_ips
        if pkt.dst_ip:
            ip_count[pkt.dst_ip] += 1

    # Three-layer filter to avoid treating router/gateway MACs as merge keys:
    # 1. src_mac only (dst_mac is the next-hop, not the actual remote host)
    # 2. Skip known infrastructure vendor MACs (Cisco, Juniper, Aruba, etc.)
    # 3. Cap group size at MAX_MERGE_GROUP_SIZE — a dual-stack host has 2–4 IPs;
    #    a router forwarding for the internet would have hundreds even after #1+#2.
    MAX_MERGE_GROUP_SIZE = 8
    mac_to_ips = {mac: ips for mac, ips in mac_to_ips.items()
                  if len(ips) <= MAX_MERGE_GROUP_SIZE}

    # Union-Find
    parent: Dict[str, str] = {ip: ip for ip in ip_count}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for mac, ips in mac_to_ips.items():
        if len(ips) < 2:
            continue
        # Merge all IPs sharing a MAC — including IPv4+IPv6 pairs (dual-stack hosts).
        # The session/edge matching layer uses node.ips (all IPs in the merged group)
        # rather than just the canonical node ID, so all original sessions are found.
        ips_list = sorted(ips)
        for ip in ips_list[1:]:
            union(ips_list[0], ip)

    groups: Dict[str, Set[str]] = defaultdict(set)
    for ip in ip_count:
        groups[find(ip)].add(ip)

    entity_map: Dict[str, str] = {}
    for root, ips in groups.items():
        canonical = _pick_canonical(ips, ip_count)
        for ip in ips:
            entity_map[ip] = canonical

    merged = [(k, v) for k, v in entity_map.items() if k != v]
    if merged:
        logger.info(f"Node merger: {len(merged)} IPs merged by MAC into canonical IDs")

    return entity_map


def _pick_canonical(ips: Set[str], ip_count: Dict[str, int]) -> str:
    v4 = [ip for ip in ips if ":" not in ip]
    v6 = [ip for ip in ips if ":" in ip]
    candidates = v4 if v4 else v6
    return max(candidates, key=lambda ip: ip_count.get(ip, 0))

