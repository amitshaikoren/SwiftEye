"""
Pre-load packet filter for the network workspace.

Applied after parallel parse (or as part of the two-phase prescan→load flow)
to narrow the packet list before sessions, graph, and plugins are built.
All fields are optional; None means "no filter on this dimension".

Filter evaluation order (each step is applied to the survivors of the previous):
  1. Protocol       — transport (L4) or application (L7) name, case-insensitive
  2. IP whitelist   — keep only packets where src OR dst matches (bare IP or CIDR)
  3. IP blacklist   — drop packets where src OR dst matches (bare IP or CIDR)
  4. Port whitelist — keep only packets where src OR dst port matches (port or range)
  5. Port blacklist — drop packets where src OR dst port matches (port or range)
  6. Top-K nodes    — keep only packets where src or dst IP is in the K busiest IPs
  7. Max            — hard cap on total packet count (safety backstop)

Whitelist and blacklist can be combined: whitelist first narrows to relevant hosts,
blacklist then carves out specific noise within that set.

Time filtering (ts_start / ts_end) is applied *inside* the parallel workers
before _parse_raw is called, so it doesn't appear here.
"""

import ipaddress
from collections import Counter
from dataclasses import dataclass
from typing import Callable, List, Optional


@dataclass
class LoadFilter:
    ts_start:       Optional[float] = None      # Unix timestamp; applied in worker loop
    ts_end:         Optional[float] = None      # Unix timestamp; applied in worker loop
    protocols:      Optional[List[str]] = None  # e.g. ["TCP", "DNS", "TLS"]
    ip_whitelist:   Optional[List[str]] = None  # keep only — e.g. ["192.168.1.1", "10.0.0.0/8"]
    ip_blacklist:   Optional[List[str]] = None  # exclude — e.g. ["10.0.0.100", "172.16.0.0/12"]
    port_whitelist: Optional[List[str]] = None  # keep only — e.g. ["80", "443", "8000-9000"]
    port_blacklist: Optional[List[str]] = None  # exclude — e.g. ["6881-6889", "4444"]
    top_k_nodes:    Optional[int] = None        # keep only packets involving the K busiest IPs
    max_packets:    int = 2_000_000


# ── matcher builders (shared by whitelist and blacklist) ──────────────────────

def _build_ip_matcher(entries: List[str]) -> Callable[[Optional[str]], bool]:
    """
    Build a function that returns True when an IP string is covered by the entry list.
    Entries may be bare IPs ("10.0.0.1") or CIDR notation ("10.0.0.0/8").
    Invalid entries are silently ignored.
    """
    networks: list = []
    exact_ips: set = set()
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        if '/' in entry:
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                pass
        else:
            exact_ips.add(entry)

    def matches(ip: Optional[str]) -> bool:
        if not ip:
            return False
        if ip in exact_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in networks)
        except ValueError:
            return False

    return matches


def _build_port_matcher(specs: List[str]) -> Callable[[Optional[int]], bool]:
    """
    Build a function that returns True when a port number matches the spec list.
    Specs may be single ports ("80") or inclusive ranges ("8000-9000").
    Invalid specs are silently ignored.
    """
    port_ranges: list = []
    exact_ports: set = set()
    for spec in specs:
        spec = str(spec).strip()
        if not spec:
            continue
        if '-' in spec:
            parts = spec.split('-', 1)
            try:
                port_ranges.append((int(parts[0]), int(parts[1])))
            except ValueError:
                pass
        else:
            try:
                exact_ports.add(int(spec))
            except ValueError:
                pass

    def matches(port: Optional[int]) -> bool:
        if port is None:
            return False
        if port in exact_ports:
            return True
        return any(lo <= port <= hi for lo, hi in port_ranges)

    return matches


# ── main filter function ──────────────────────────────────────────────────────

def apply_post_parse_filter(packets: list, f: LoadFilter) -> list:
    """
    Apply protocol, IP/subnet (white+black), port (white+black), and top-K filters.
    Returns a new (possibly shorter) list; does not mutate the originals.
    """
    if not packets:
        return packets

    # ── Protocol filter ───────────────────────────────────────────────
    if f.protocols:
        proto_set = {p.upper() for p in f.protocols}
        packets = [
            p for p in packets
            if (p.protocol or '').upper() in proto_set
            or (p.transport or '').upper() in proto_set
        ]

    # ── IP whitelist ──────────────────────────────────────────────────
    if f.ip_whitelist:
        ip_wl = _build_ip_matcher(f.ip_whitelist)
        packets = [p for p in packets if ip_wl(p.src_ip) or ip_wl(p.dst_ip)]

    # ── IP blacklist ──────────────────────────────────────────────────
    if f.ip_blacklist:
        ip_bl = _build_ip_matcher(f.ip_blacklist)
        packets = [p for p in packets if not (ip_bl(p.src_ip) or ip_bl(p.dst_ip))]

    # ── Port whitelist ────────────────────────────────────────────────
    if f.port_whitelist:
        port_wl = _build_port_matcher(f.port_whitelist)
        packets = [p for p in packets if port_wl(p.src_port) or port_wl(p.dst_port)]

    # ── Port blacklist ────────────────────────────────────────────────
    if f.port_blacklist:
        port_bl = _build_port_matcher(f.port_blacklist)
        packets = [p for p in packets if not (port_bl(p.src_port) or port_bl(p.dst_port))]

    # ── Top-K nodes ───────────────────────────────────────────────────
    # Count each IP's total involvement (src + dst appearances), keep the K busiest.
    if f.top_k_nodes and f.top_k_nodes > 0:
        ip_counts: Counter = Counter()
        for p in packets:
            if p.src_ip:
                ip_counts[p.src_ip] += 1
            if p.dst_ip:
                ip_counts[p.dst_ip] += 1
        top_ip_set = {ip for ip, _ in ip_counts.most_common(f.top_k_nodes)}
        packets = [p for p in packets if p.src_ip in top_ip_set or p.dst_ip in top_ip_set]

    return packets[: f.max_packets]
