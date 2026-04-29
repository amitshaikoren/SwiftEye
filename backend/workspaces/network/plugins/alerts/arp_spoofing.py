"""
ARP spoofing detector.

Detection 1 — IP claimed by multiple MACs:
  Iterates ARP packets (not sessions) to build an accurate {IP: set(MACs)} map.
  Sessions aggregate MACs into sets and lose per-packet MAC-IP binding.

Detection 2 — Gratuitous ARP flood:
  High volume of gratuitous ARP replies (sender IP == target IP) from a single host.
"""

import uuid
from workspaces.network.plugins.alerts import AlertPluginBase, AlertRecord

_GRATUITOUS_THRESHOLD = 15


class ArpSpoofingDetector(AlertPluginBase):
    name = "arp_spoofing"
    version = "1.0"

    def detect(self, ctx):
        alerts = []

        # -- Detection 1: IP claimed by multiple MACs --
        # Build {ip: {mac: first_timestamp}} from raw packets for accurate binding
        ip_mac_map = {}  # ip -> {mac: earliest_ts}
        for pkt in ctx.packets:
            if pkt.protocol != "ARP":
                continue
            ex = pkt.extra
            src_ip = ex.get("arp_src_ip")
            src_mac = ex.get("arp_src_mac")
            if not src_ip or not src_mac:
                continue
            if src_ip not in ip_mac_map:
                ip_mac_map[src_ip] = {}
            if src_mac not in ip_mac_map[src_ip]:
                ip_mac_map[src_ip][src_mac] = pkt.timestamp

        for ip, macs in ip_mac_map.items():
            if len(macs) < 2:
                continue
            evidence = []
            for mac, ts in sorted(macs.items(), key=lambda x: x[1]):
                evidence.append({
                    "key": "MAC",
                    "value": mac,
                    "note": f"first seen at {ts:.3f}",
                })
            alerts.append(AlertRecord(
                id=uuid.uuid4().hex[:8],
                title="ARP Spoofing",
                subtitle=f"IP {ip} claimed by {len(macs)} different MAC addresses",
                severity="high",
                detector=self.name,
                source="detector",
                source_name=self.name,
                timestamp=min(macs.values()),
                src_ip=ip,
                dst_ip=None,
                evidence=evidence,
                node_ids=[ip],
            ))

        # -- Detection 2: Gratuitous ARP flood --
        # Gratuitous = ARP reply where sender IP == target IP
        grat_counts = {}  # src_ip -> {count, first_ts}
        for pkt in ctx.packets:
            if pkt.protocol != "ARP":
                continue
            ex = pkt.extra
            opcode = ex.get("arp_opcode")
            src_ip = ex.get("arp_src_ip")
            dst_ip = ex.get("arp_dst_ip")
            if opcode == 2 and src_ip and src_ip == dst_ip:
                if src_ip not in grat_counts:
                    grat_counts[src_ip] = {"count": 0, "first_ts": pkt.timestamp}
                grat_counts[src_ip]["count"] += 1

        for ip, info in grat_counts.items():
            if info["count"] < _GRATUITOUS_THRESHOLD:
                continue
            alerts.append(AlertRecord(
                id=uuid.uuid4().hex[:8],
                title="ARP Anomaly",
                subtitle=f"High volume of gratuitous ARP replies from {ip}",
                severity="medium",
                detector=self.name,
                source="detector",
                source_name=self.name,
                timestamp=info["first_ts"],
                src_ip=ip,
                dst_ip=None,
                evidence=[
                    {"key": "Gratuitous replies", "value": str(info["count"]), "note": "sender IP == target IP"},
                ],
                node_ids=[ip],
            ))

        return alerts
