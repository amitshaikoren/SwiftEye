"""
Pre-load packet filter for the network workspace.

Applied after parallel parse (or as part of the two-phase prescan→load flow)
to narrow the packet list before sessions, graph, and plugins are built.
All fields are optional; None means "no filter on this dimension".

Filter evaluation order (each step is applied to the survivors of the previous):
  1. Protocol  — transport (L4) or application (L7) name, case-insensitive
  2. IP        — src or dst IP must match any entry (bare IP or CIDR subnet)
  3. Port      — src or dst port must match any entry (single port or range)
  4. Top-K     — keep only packets belonging to the K busiest flows
  5. Max       — hard cap on total packet count (safety backstop)

Time filtering (ts_start / ts_end) is applied *inside* the parallel workers
before _parse_raw is called, so it doesn't appear here.
"""

import ipaddress
from collections import Counter
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class LoadFilter:
    ts_start:       Optional[float] = None      # Unix timestamp; applied in worker loop
    ts_end:         Optional[float] = None      # Unix timestamp; applied in worker loop
    protocols:      Optional[List[str]] = None  # e.g. ["TCP", "DNS", "TLS"]
    ip_whitelist:   Optional[List[str]] = None  # e.g. ["192.168.1.1", "10.0.0.0/8"]
    port_whitelist: Optional[List[str]] = None  # e.g. ["80", "443", "8000-9000"]
    top_k_flows:    Optional[int] = None        # keep only top-K busiest session flows
    max_packets:    int = 2_000_000


def apply_post_parse_filter(packets: list, f: LoadFilter) -> list:
    """
    Apply protocol, IP/subnet, port, and top-K filters to a packet list.
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

    # ── IP / CIDR whitelist ───────────────────────────────────────────
    if f.ip_whitelist:
        networks: list = []
        exact_ips: set = set()
        for entry in f.ip_whitelist:
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

        def _ip_matches(ip: Optional[str]) -> bool:
            if not ip:
                return False
            if ip in exact_ips:
                return True
            try:
                addr = ipaddress.ip_address(ip)
                return any(addr in net for net in networks)
            except ValueError:
                return False

        packets = [p for p in packets if _ip_matches(p.src_ip) or _ip_matches(p.dst_ip)]

    # ── Port / range whitelist ────────────────────────────────────────
    if f.port_whitelist:
        port_ranges: list = []
        exact_ports: set = set()
        for spec in f.port_whitelist:
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

        def _port_matches(port: Optional[int]) -> bool:
            if port is None:
                return False
            if port in exact_ports:
                return True
            return any(lo <= port <= hi for lo, hi in port_ranges)

        packets = [
            p for p in packets
            if _port_matches(p.src_port) or _port_matches(p.dst_port)
        ]

    # ── Top-K flows ───────────────────────────────────────────────────
    # session_key is a property on PacketRecord; no need to call build_sessions first.
    if f.top_k_flows and f.top_k_flows > 0:
        flow_counts: Counter = Counter(p.session_key for p in packets)
        top_keys = {key for key, _ in flow_counts.most_common(f.top_k_flows)}
        packets = [p for p in packets if p.session_key in top_keys]

    return packets[: f.max_packets]
