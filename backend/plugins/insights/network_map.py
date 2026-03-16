"""
Network Map Plugin for SwiftEye.

Passively identifies network topology from captured traffic:
  - ARP table: IP -> MAC mappings from ARP requests/replies
  - Gateways: MACs that appear as dst_mac on traffic to external IPs
  - LAN hosts: IPs confirmed on the same broadcast domain
  - Hop estimation: TTL-based distance from capture point to external IPs
  - Network role per node: Gateway / LAN host / External (N hops)

UI slots:
  - node_detail_section "network_role"  -- role, hops, ARP MAC, routes-for count
  - stats_section "network_map_summary" -- gateway list, LAN count, ARP table size
"""

from typing import Dict, Any, List, Set
from collections import defaultdict
from .. import PluginBase, UISlot, AnalysisContext, display_rows, display_text, display_list


_PRIVATE_PREFIXES = (
    "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "169.254.",
)


def _is_private(ip: str) -> bool:
    return bool(ip) and ":" not in ip and any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _is_external(ip: str) -> bool:
    if not ip or ":" in ip or ip.startswith("127.") or ip.startswith("0."):
        return False
    return not _is_private(ip)


def _initial_ttl(ttl: int) -> int:
    for init in (32, 64, 128, 255):
        if ttl <= init:
            return init
    return 255


def _hops(ttl: int) -> int:
    return _initial_ttl(ttl) - ttl if ttl > 0 else -1


class NetworkMapPlugin(PluginBase):
    name        = "network_map"
    description = "Passive network topology: gateways, LAN hosts, hop counts, ARP table"

    def get_ui_slots(self) -> List[UISlot]:
        return [
            UISlot(
                slot_type="node_detail_section",
                slot_id="network_role",
                title="Network Role",
                priority=15,
                default_open=True,
            ),
            UISlot(
                slot_type="stats_section",
                slot_id="network_map_summary",
                title="Network Map",
                priority=55,
            ),
        ]

    def analyze_global(self, ctx: AnalysisContext) -> Dict[str, Any]:
        packets = ctx.packets

        # -- ARP table -----------------------------------------------
        arp_table: Dict[str, str] = {}
        mac_to_ips: Dict[str, Set[str]] = defaultdict(set)

        for pkt in packets:
            if pkt.transport == "ARP" or pkt.protocol == "ARP":
                for ip, mac in [(pkt.src_ip, pkt.src_mac), (pkt.dst_ip, pkt.dst_mac)]:
                    if ip and mac and mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "") \
                            and _is_private(ip):
                        arp_table[ip] = mac
                        mac_to_ips[mac].add(ip)

        # -- Gateway identification -----------------------------------
        gw_mac_ext: Dict[str, Set[str]] = defaultdict(set)
        for pkt in packets:
            if _is_external(pkt.dst_ip) and pkt.dst_mac \
                    and pkt.dst_mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", ""):
                gw_mac_ext[pkt.dst_mac].add(pkt.dst_ip)

        gateway_macs: Set[str] = {m for m, ips in gw_mac_ext.items() if len(ips) >= 3}
        mac_to_ip_rev = {mac: ip for ip, mac in arp_table.items()}
        gateway_ips: Dict[str, int] = {}
        for mac in gateway_macs:
            ip = mac_to_ip_rev.get(mac, f"gw:{mac[:8]}")
            gateway_ips[ip] = len(gw_mac_ext[mac])

        # -- LAN hosts -----------------------------------------------
        lan_ips: Set[str] = set(arp_table.keys())
        for pkt in packets:
            for ip, ttl in [(pkt.src_ip, pkt.ttl), (pkt.dst_ip, pkt.ttl)]:
                if ip and _is_private(ip) and ttl > 0 and _hops(ttl) == 0:
                    lan_ips.add(ip)

        # -- Hop estimation ------------------------------------------
        ext_ttls: Dict[str, List[int]] = defaultdict(list)
        for pkt in packets:
            if _is_external(pkt.src_ip) and pkt.ttl > 0:
                ext_ttls[pkt.src_ip].append(pkt.ttl)

        external_hops: Dict[str, int] = {}
        for ip, ttls in ext_ttls.items():
            h = _hops(max(ttls))
            if h >= 0:
                external_hops[ip] = h

        # -- Per-IP role map -----------------------------------------
        all_ips: Set[str] = set()
        for pkt in packets:
            if pkt.src_ip:
                all_ips.add(pkt.src_ip)
            if pkt.dst_ip:
                all_ips.add(pkt.dst_ip)

        network_role: Dict[str, Dict] = {}
        for ip in all_ips:
            if not ip or ":" in ip:
                continue
            mac    = arp_table.get(ip)
            shared = sorted(mac_to_ips.get(mac, set())) if mac else []

            if ip in gateway_ips:
                role, hops = "gateway", 0
            elif ip in lan_ips:
                role, hops = "lan", 0
            elif _is_external(ip):
                role, hops = "external", external_hops.get(ip)
            else:
                role, hops = "lan", None

            network_role[ip] = {
                "role":    role,
                "hops":    hops,
                "arp_mac": mac,
                "gw_for":  gateway_ips.get(ip, 0),
                "arp_ips": shared,
            }

        # -- Summary -------------------------------------------------
        gw_list = sorted(gateway_ips, key=lambda x: gateway_ips[x], reverse=True)
        summary_display = display_rows({
            "ARP entries":  str(len(arp_table)),
            "LAN hosts":    str(len(lan_ips)),
            "Gateways":     ", ".join(gw_list[:3]) if gw_list else "none detected",
        })

        return {
            "network_role": network_role,
            "network_map_summary": {
                "gateways":      gw_list,
                "lan_count":     len(lan_ips),
                "arp_count":     len(arp_table),
                "arp_table":     arp_table,
                "external_hops": external_hops,
                "_display":      summary_display,
            },
        }
