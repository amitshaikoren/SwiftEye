"""
ARP session field accumulation.

Collects ARP opcodes (request/reply), sender and target MAC/IP pairs,
and broadcast flags. No direction splitting — ARP is a flat L2 protocol.

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — unused for ARP (no direction split)
    source_type — "tshark" or None (pcap)
"""


def init():
    return {
        "arp_opcodes": [],
        "arp_src_macs": set(),
        "arp_dst_macs": set(),
        "arp_src_ips": set(),
        "arp_dst_ips": set(),
        "arp_broadcast_count": 0,
    }


def accumulate(s, ex, is_fwd, source_type):
    if ex.get("arp_opcode") is None:
        return
    opcode_name = ex.get("arp_opcode_name", str(ex["arp_opcode"]))
    s["arp_opcodes"].append(opcode_name)
    if ex.get("arp_src_mac"):
        s["arp_src_macs"].add(ex["arp_src_mac"])
    if ex.get("arp_dst_mac"):
        s["arp_dst_macs"].add(ex["arp_dst_mac"])
    if ex.get("arp_src_ip"):
        s["arp_src_ips"].add(ex["arp_src_ip"])
    if ex.get("arp_dst_ip"):
        s["arp_dst_ips"].add(ex["arp_dst_ip"])
    if ex.get("arp_broadcast"):
        s["arp_broadcast_count"] += 1


def _opcode_counts(opcode_list):
    """Aggregate opcodes by frequency, most common first."""
    counts = {}
    for op in opcode_list:
        counts[op] = counts.get(op, 0) + 1
    return [{"opcode": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])]


def serialize(s):
    s["arp_opcodes"] = _opcode_counts(s["arp_opcodes"])
    s["arp_src_macs"] = sorted(s["arp_src_macs"])
    s["arp_dst_macs"] = sorted(s["arp_dst_macs"])
    s["arp_src_ips"] = sorted(s["arp_src_ips"])
    s["arp_dst_ips"] = sorted(s["arp_dst_ips"])
