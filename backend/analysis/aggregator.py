"""
Data aggregation for SwiftEye.

Core viewer layer — structures raw packet data for display.
Handles:
- Time bucketing (configurable interval)
- Node/edge graph construction  
- Subnet grouping
- Filtering
- Researcher metadata overlay (pass-through, not interpretation)

This layer does NOT interpret data. If something requires correlation,
inference, or domain knowledge, it belongs in the plugin layer instead.
See plugins/dns_resolver.py for an example.
"""

import math
import logging
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict
from ipaddress import IPv4Network, IPv4Address

from parser.packet import PacketRecord
from parser.oui import lookup_vendor
from parser.ja3_db import lookup_ja3

logger = logging.getLogger("swifteye.aggregator")


def build_time_buckets(
    packets: List[PacketRecord],
    bucket_seconds: int = 15,
) -> List[Dict[str, Any]]:
    """
    Group packets into time buckets, collapsing large empty gaps into a single
    gap marker bucket.

    Gap collapse rule: if a run of empty buckets represents a gap of both
    > 10% of total capture duration AND > 5 minutes (300s), it is replaced by
    a single bucket with is_gap=True. This prevents 3-day captures from
    producing hundreds of thousands of empty buckets.

    Returns list of bucket dicts:
      Normal:  {index, start_time, end_time, packet_count, total_bytes, protocols}
      Gap:     {index, start_time, end_time, packet_count:0, total_bytes:0,
                protocols:{}, is_gap:True, gap_seconds:<float>}
    """
    if not packets:
        return []

    min_t = packets[0].timestamp
    max_t = packets[-1].timestamp
    total_sec = max(1.0, max_t - min_t)

    # Cap raw buckets at 5000 to prevent memory/performance issues on long captures.
    # If the requested bucket_seconds would exceed this, widen the bucket size.
    MAX_RAW_BUCKETS = 15000
    effective_bucket_sec = bucket_seconds
    if total_sec / effective_bucket_sec > MAX_RAW_BUCKETS:
        effective_bucket_sec = math.ceil(total_sec / MAX_RAW_BUCKETS)
        logger.debug("Bucket size auto-adjusted from %ds to %ds (capture spans %.0fs)",
                      bucket_seconds, effective_bucket_sec, total_sec)
    bucket_seconds = effective_bucket_sec

    num_buckets = max(1, math.ceil(total_sec / bucket_seconds))

    raw: List[Dict[str, Any]] = []
    for i in range(num_buckets):
        raw.append({
            "index": i,
            "start_time": min_t + i * bucket_seconds,
            "end_time": min_t + (i + 1) * bucket_seconds,
            "packet_count": 0,
            "total_bytes": 0,
            "protocols": defaultdict(int),
        })

    for pkt in packets:
        bi = min(int((pkt.timestamp - min_t) / bucket_seconds), num_buckets - 1)
        raw[bi]["packet_count"] += 1
        raw[bi]["total_bytes"] += pkt.orig_len
        raw[bi]["protocols"][pkt.protocol] += 1

    for b in raw:
        b["protocols"] = dict(b["protocols"])

    # ── Gap collapse ─────────────────────────────────────────────────
    # Threshold: gap must be both >20% of total duration AND >10 minutes (600s).
    min_gap_sec = max(600.0, total_sec * 0.20)
    min_gap_buckets = math.ceil(min_gap_sec / bucket_seconds)

    result: List[Dict[str, Any]] = []
    i = 0
    out_idx = 0
    while i < len(raw):
        if raw[i]["packet_count"] > 0:
            b = dict(raw[i])
            b["index"] = out_idx
            result.append(b)
            out_idx += 1
            i += 1
        else:
            # Scan ahead for the full run of empty buckets
            run_start = i
            while i < len(raw) and raw[i]["packet_count"] == 0:
                i += 1
            run_len = i - run_start
            if run_len >= min_gap_buckets:
                # Collapse to a single gap marker
                gap_start = raw[run_start]["start_time"]
                gap_end   = raw[i - 1]["end_time"]
                result.append({
                    "index": out_idx,
                    "start_time": gap_start,
                    "end_time": gap_end,
                    "packet_count": 0,
                    "total_bytes": 0,
                    "protocols": {},
                    "is_gap": True,
                    "gap_seconds": gap_end - gap_start,
                })
                out_idx += 1
            else:
                # Small gap — keep individual empty buckets
                for j in range(run_start, i):
                    b = dict(raw[j])
                    b["index"] = out_idx
                    result.append(b)
                    out_idx += 1

    return result


def filter_packets(
    packets: List[PacketRecord],
    time_range: Optional[tuple] = None,
    protocols: Optional[Set[str]] = None,
    protocol_filters: Optional[Set[str]] = None,
    ip_filter: str = "",
    port_filter: str = "",
    search_query: str = "",
    include_ipv6: bool = True,
) -> List[PacketRecord]:
    """
    Apply standard packet filters and return the filtered list.

    Extracted so that the research chart endpoint and build_graph both apply
    identical filtering logic — no duplication, no drift.

    Args:
        time_range:    (start_ts, end_ts) Unix seconds, or None for no filter.
        protocols:     Set of protocol names to include, or None for all.
                       Legacy flat filter — used when protocol_filters is not set.
        protocol_filters: Set of composite keys "ipv/transport/protocol" e.g.
                       "4/TCP/HTTPS", "6/UDP/DNS". When set, overrides `protocols`.
                       Each packet must match at least one key to be included.
        ip_filter:     Substring match against src_ip or dst_ip only.
        port_filter:   Integer port string to match src_port or dst_port.
        search_query:  Broad substring match — src_ip, dst_ip, src_mac, dst_mac,
                       protocol, tcp_flags, src_port, dst_port. Supersedes ip_filter
                       and port_filter for the general search use case.
        include_ipv6:  When False, drop packets whose src or dst IP contains ':'.
    """
    filtered = packets

    if not include_ipv6:
        filtered = [p for p in filtered if ":" not in p.src_ip and ":" not in p.dst_ip]

    if time_range:
        t_start, t_end = time_range
        filtered = [p for p in filtered if t_start <= p.timestamp <= t_end]

    if protocol_filters:
        # Composite filter: each key is "ipv/transport/protocol"
        # ip_version 0 is a wildcard (matches any ip_version — used for non-IP protocols like ARP)
        pf_set = set()
        pf_wildcard = set()  # (transport, protocol) tuples where ipv=0
        for key in protocol_filters:
            parts = key.split("/")
            if len(parts) == 3:
                ipv = int(parts[0])
                if ipv == 0:
                    pf_wildcard.add((parts[1], parts[2]))
                else:
                    pf_set.add((ipv, parts[1], parts[2]))
        if pf_set or pf_wildcard:
            filtered = [p for p in filtered if
                (p.ip_version, p.transport, p.protocol) in pf_set or
                (p.transport, p.protocol) in pf_wildcard]
    elif protocols:
        filtered = [p for p in filtered if p.protocol in protocols]

    if ip_filter:
        q = ip_filter.lower()
        filtered = [p for p in filtered if q in p.src_ip.lower() or q in p.dst_ip.lower()]

    if port_filter:
        try:
            pf = int(port_filter)
            filtered = [p for p in filtered if p.src_port == pf or p.dst_port == pf]
        except ValueError:
            pass

    if search_query:
        q = search_query.lower()
        filtered = [p for p in filtered if (
            q in p.src_ip.lower() or
            q in p.dst_ip.lower() or
            q in p.src_mac.lower() or
            q in p.dst_mac.lower() or
            q in p.protocol.lower() or
            q in p.tcp_flags_str.lower() or
            q in str(p.src_port) or
            q in str(p.dst_port)
        )]

    return filtered


def build_mac_split_map(packets: List[PacketRecord]) -> Dict[str, set]:
    """
    Detect IPs that appear with more than one distinct source MAC address.

    This handles the case where two physically different hosts share the same
    IP (e.g. during an IP conflict, after a DHCP reassignment, or in lab
    environments with cloned VMs). Without this, both hosts collapse into one
    node because the node ID is the IP.

    Returns a dict: { ip → set_of_macs } but ONLY for IPs that have ≥ 2
    distinct MACs. The caller passes this to build_graph() as mac_split_map.
    When an IP appears in this dict, get_node_id() appends ::mac to the node
    ID so each (ip, mac) pair becomes a separate node.

    Caveats / exclusions (same as node_merger):
    - Only src_ip/src_mac pairs — dst_mac is next-hop, not destination host
    - Skip broadcast/multicast MACs and known infrastructure vendor MACs
    - Skip blank or zero MACs
    """
    _INFRA_VENDORS = {
        "cisco", "juniper", "aruba", "ubiquiti", "palo alto",
        "fortinet", "sophos", "watchguard", "brocade", "extreme",
        "arista", "mikrotik", "ruckus", "meraki",
    }

    def _skip_mac(mac: str) -> bool:
        if not mac or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return True
        m = mac.lower()
        if m.startswith("33:33:") or m.startswith("01:00:5e:"):
            return True  # multicast
        vendor = (lookup_vendor(mac) or "").lower()
        return any(v in vendor for v in _INFRA_VENDORS)

    ip_to_macs: Dict[str, set] = defaultdict(set)
    for pkt in packets:
        if pkt.src_ip and pkt.src_mac and not _skip_mac(pkt.src_mac):
            ip_to_macs[pkt.src_ip].add(pkt.src_mac)

    # Only return IPs with 2+ distinct MACs
    return {ip: macs for ip, macs in ip_to_macs.items() if len(macs) >= 2}


def build_graph(
    packets: List[PacketRecord],
    time_range: Optional[tuple] = None,
    protocols: Optional[Set[str]] = None,
    protocol_filters: Optional[Set[str]] = None,
    ip_filter: str = "",
    port_filter: str = "",
    flag_filter: str = "",
    search_query: str = "",
    subnet_grouping: bool = False,
    subnet_prefix: int = 24,
    hostname_map: Optional[Dict[str, Set[str]]] = None,
    metadata_map: Optional[Dict[str, Dict[str, Any]]] = None,
    entity_map: Optional[Dict[str, str]] = None,
    include_ipv6: bool = True,
    subnet_exclusions: Optional[set] = None,
    mac_split_map: Optional[Dict[str, set]] = None,
) -> Dict[str, Any]:
    """
    Build a graph (nodes + edges) from packets with filtering.

    Args:
        hostname_map: IP → set of hostnames (from DNS responses)
        metadata_map: IP → researcher-provided metadata dict
        entity_map:   IP → canonical IP (from pre-aggregation plugins).
                      IPs that map to the same canonical ID are merged into
                      one node. Pass None or {} for no merging.

    include_ipv6: When False, skip packets where src_ip or dst_ip contains ':'.
                  Reduces noise from link-local/multicast IPv6 in dual-stack captures.

    Returns: { nodes: [...], edges: [...], filtered_count: int, filtered_bytes: int }
    """
    # Resolve an IP through the entity map (identity if not present)
    _em = entity_map or {}
    def resolve(ip: str) -> str:
        return _em.get(ip, ip)

    # Apply standard filters.
    # When include_ipv6=False AND merge_by_mac is active: run the filter on RESOLVED
    # IPs rather than raw packet IPs. A packet from 2a0d:6fc0::1 (local IPv6) →
    # 2606:4700:: (external) would normally be dropped because src has ':'. But after
    # entity resolution the source becomes 192.168.1.177 (IPv4). We should keep it —
    # the resolved graph edge is IPv4 → external-IPv6, which the user's toggle intends
    # to show. We only drop packets where BOTH resolved endpoints are IPv6.
    if not include_ipv6 and _em:
        def _include_packet(p) -> bool:
            if ":" not in p.src_ip and ":" not in p.dst_ip:
                return True  # pure IPv4 packet — always included
            src_r = _em.get(p.src_ip, p.src_ip)
            dst_r = _em.get(p.dst_ip, p.dst_ip)
            # Keep if at least one resolved endpoint is IPv4
            return ":" not in src_r or ":" not in dst_r
        pre_ipv6_filtered = [p for p in packets if _include_packet(p)]
        filtered = filter_packets(
            pre_ipv6_filtered,
            time_range=time_range,
            protocols=protocols,
            protocol_filters=protocol_filters,
            ip_filter=ip_filter,
            port_filter=port_filter,
            include_ipv6=True,   # already handled above
        )
    else:
        filtered = filter_packets(
            packets,
            time_range=time_range,
            protocols=protocols,
            protocol_filters=protocol_filters,
            ip_filter=ip_filter,
            port_filter=port_filter,
            include_ipv6=include_ipv6,
        )

    if flag_filter:
        ff = flag_filter.upper()
        filtered = [p for p in filtered if ff in p.tcp_flags_str]

    if search_query:
        q = search_query.lower()
        filtered = [p for p in filtered if (
            q in p.src_ip.lower() or
            q in p.dst_ip.lower() or
            q in p.src_mac.lower() or
            q in p.dst_mac.lower() or
            q in p.protocol.lower() or
            q in p.tcp_flags_str.lower() or
            q in str(p.src_port) or
            q in str(p.dst_port)
        )]
    
    # Build graph
    _excl = subnet_exclusions or set()
    _mac_split = mac_split_map or {}  # IP → set of MACs (only IPs with 2+ distinct MACs)
    def get_node_id(ip: str, mac: str = "") -> Optional[str]:
        if not ip:
            return None
        # Apply entity map first (merge same-host IPs into canonical),
        # then check mac_split_map to keep same-IP different-MAC hosts separate
        canonical = resolve(ip)
        if canonical in _mac_split and mac:
            # IP appears with multiple distinct MACs → differentiate by MAC
            canonical = f"{canonical}::{mac}"
        if subnet_grouping and "::" not in canonical and ":" not in canonical.split("::")[0] and canonical != "ARP":
            try:
                base_ip = canonical.split("::")[0] if "::" in canonical else canonical
                net = IPv4Network(f"{base_ip}/{subnet_prefix}", strict=False)
                net_str = str(net)
                if net_str in _excl:
                    return canonical
                return net_str
            except Exception:
                return canonical
        return canonical
    
    node_map: Dict[str, Dict] = {}
    edge_map: Dict[str, Dict] = {}
    
    for pkt in filtered:
        src_id = get_node_id(pkt.src_ip, pkt.src_mac)
        dst_id = get_node_id(pkt.dst_ip, pkt.dst_mac)
        if not src_id or not dst_id or src_id == dst_id:
            continue
        
        # Build nodes
        for nid, ip, mac in [(src_id, pkt.src_ip, pkt.src_mac), (dst_id, pkt.dst_ip, pkt.dst_mac)]:
            if nid not in node_map:
                node_map[nid] = {
                    "id": nid,
                    "is_subnet": subnet_grouping and "/" in nid,
                    "ips": set(),
                    "macs": set(),
                    "total_bytes": 0,
                    "packet_count": 0,
                    "protocols": set(),
                    "ttls": set(),
                }
            n = node_map[nid]
            n["ips"].add(ip)
            if mac:
                n["macs"].add(mac)
            n["total_bytes"] += pkt.orig_len
            n["packet_count"] += 1
            n["protocols"].add(pkt.protocol)
            # Track TTLs with direction: if this IP is src, it's outgoing TTL
            if pkt.ttl > 0:
                if ip == pkt.src_ip:
                    if "ttls_out" not in n:
                        n["ttls_out"] = set()
                    n["ttls_out"].add(pkt.ttl)
                else:
                    if "ttls_in" not in n:
                        n["ttls_in"] = set()
                    n["ttls_in"].add(pkt.ttl)
        
        # Build edges
        ek = tuple(sorted([src_id, dst_id]))
        edge_key = f"{ek[0]}|{ek[1]}|{pkt.protocol}"
        if edge_key not in edge_map:
            edge_map[edge_key] = {
                "id": edge_key,
                "source": ek[0],
                "target": ek[1],
                "protocol": pkt.protocol,
                "total_bytes": 0,
                "packet_count": 0,
                "first_seen": pkt.timestamp,
                "last_seen": pkt.timestamp,
                "tls_snis": set(),
                "tls_versions": set(),
                "tls_ciphers": set(),
                "tls_selected_ciphers": set(),
                "http_hosts": set(),
                "dns_queries": set(),
                "ports": set(),
                "ja3_hashes": set(),
                "ja4_hashes": set(),
                "has_protocol_conflict": False,
                "protocol_by_port": set(),
                "protocol_by_payload": set(),
            }
        e = edge_map[edge_key]
        e["total_bytes"] += pkt.orig_len
        e["packet_count"] += 1
        e["last_seen"] = max(e["last_seen"], pkt.timestamp)
        if pkt.src_port > 0:
            e["ports"].add(pkt.src_port)
        if pkt.dst_port > 0:
            e["ports"].add(pkt.dst_port)
        # Track protocol detection conflicts
        if pkt.protocol_conflict:
            e["has_protocol_conflict"] = True
        if pkt.protocol_by_port:
            e["protocol_by_port"].add(pkt.protocol_by_port)
        if pkt.protocol_by_payload:
            e["protocol_by_payload"].add(pkt.protocol_by_payload)
        # Collect TLS/HTTP/DNS extras
        ex = pkt.extra
        if ex:
            if ex.get("tls_sni"):
                e["tls_snis"].add(ex["tls_sni"])
            if ex.get("tls_hello_version"):
                e["tls_versions"].add(ex["tls_hello_version"])
            if ex.get("tls_selected_cipher"):
                e["tls_selected_ciphers"].add(ex["tls_selected_cipher"])
            if ex.get("tls_cipher_suites"):
                for cs in ex["tls_cipher_suites"][:10]:
                    e["tls_ciphers"].add(cs)
            if ex.get("http_host"):
                e["http_hosts"].add(ex["http_host"])
            if ex.get("dns_query"):
                e["dns_queries"].add(ex["dns_query"])
            if ex.get("ja3"):
                e["ja3_hashes"].add(ex["ja3"])
            if ex.get("ja4"):
                e["ja4_hashes"].add(ex["ja4"])
    
    # Serialize sets
    hn_map = hostname_map or {}
    md_map = metadata_map or {}
    
    nodes = []
    for n in node_map.values():
        ttls_out = sorted(n.get("ttls_out", set()))
        ttls_in = sorted(n.get("ttls_in", set()))
        
        # Collect hostnames for all IPs in this node
        hostnames = set()
        for ip in n["ips"]:
            if ip in hn_map:
                hostnames.update(hn_map[ip])
        
        # Collect researcher metadata for all IPs in this node
        meta = {}
        for ip in n["ips"]:
            if ip in md_map:
                meta = {**meta, **md_map[ip]}
        
        node_data = {
            "id": n["id"],
            "is_subnet": n["is_subnet"],
            "ips": sorted(n["ips"]),
            "macs": sorted(n["macs"]),
            "mac_vendors": [lookup_vendor(mac) for mac in sorted(n["macs"])],
            "protocols": sorted(n["protocols"]),
            "total_bytes": n["total_bytes"],
            "packet_count": n["packet_count"],
            "ttls_out": _ttl_list(ttls_out),
            "ttls_in": _ttl_list(ttls_in),
            "is_private": _any_private(n["ips"]),
            "hostnames": sorted(hostnames),
        }
        if meta:
            node_data["metadata"] = meta
        
        nodes.append(node_data)
    
    edges = []
    for e in edge_map.values():
        edge_data = {
            "id": e["id"],
            "source": e["source"],
            "target": e["target"],
            "protocol": e["protocol"],
            "total_bytes": e["total_bytes"],
            "packet_count": e["packet_count"],
            "first_seen": e["first_seen"],
            "last_seen": e["last_seen"],
            "ports": sorted(e["ports"]),
            "tls_snis": sorted(e["tls_snis"]),
            "tls_versions": sorted(e["tls_versions"]),
            "tls_ciphers": sorted(e["tls_ciphers"])[:15],
            "tls_selected_ciphers": sorted(e["tls_selected_ciphers"]),
            "http_hosts": sorted(e["http_hosts"]),
            "dns_queries": sorted(e["dns_queries"])[:30],
            "ja3_hashes": sorted(e["ja3_hashes"]),
            "ja4_hashes": sorted(e["ja4_hashes"]),
        }
        if e.get("has_protocol_conflict"):
            edge_data["protocol_conflict"] = True
            edge_data["protocol_by_port"] = sorted(e["protocol_by_port"])
            edge_data["protocol_by_payload"] = sorted(e["protocol_by_payload"])
        edges.append(edge_data)
    
    # ── Post-filter: remove external IPv6 nodes when include_ipv6=False ──
    # The packet-level IPv6 filter (above) keeps packets where at least one
    # resolved endpoint is IPv4 — this is correct for preserving merged
    # dual-stack traffic. But it leaves behind graph nodes for external IPv6
    # addresses (e.g. 2606:4700::) that the user intended to hide with the
    # "Show IPv6" toggle. Remove those nodes and their edges.
    if not include_ipv6 and _em:
        ipv6_node_ids = {n["id"] for n in nodes if ":" in n["id"]}
        if ipv6_node_ids:
            nodes = [n for n in nodes if n["id"] not in ipv6_node_ids]
            edges = [e for e in edges if e["source"] not in ipv6_node_ids
                     and e["target"] not in ipv6_node_ids]

    return {
        "nodes": nodes,
        "edges": edges,
        "filtered_count": len(filtered),
        "filtered_bytes": sum(p.orig_len for p in filtered),
    }


def get_subnets(packets: List[PacketRecord], prefix: int = 24) -> Dict[str, List[str]]:
    """Group all unique IPs into subnets."""
    all_ips = set()
    for p in packets:
        if p.src_ip and ":" not in p.src_ip:
            all_ips.add(p.src_ip)
        if p.dst_ip and ":" not in p.dst_ip:
            all_ips.add(p.dst_ip)
    
    subnets: Dict[str, Set[str]] = defaultdict(set)
    for ip in all_ips:
        try:
            net = IPv4Network(f"{ip}/{prefix}", strict=False)
            subnets[str(net)].add(ip)
        except Exception:
            pass
    
    return {k: sorted(v) for k, v in subnets.items()}


def _any_private(ips) -> bool:
    for ip in ips:
        if _is_private(ip):
            return True
    return False


def _ttl_list(ttls: list) -> list:
    """Return sorted unique TTL values. Researchers need exact numbers, not buckets."""
    return sorted(set(ttls))


def _is_private(ip: str) -> bool:
    if not ip or ":" in ip:
        return False
    try:
        a = IPv4Address(ip)
        return a.is_private
    except Exception:
        return False
