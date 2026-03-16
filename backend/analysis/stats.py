"""
Statistics computation for SwiftEye.
"""

from typing import List, Dict, Any
from collections import defaultdict, Counter

from parser.packet import PacketRecord
from constants import WELL_KNOWN_PORTS


def compute_global_stats(packets: List[PacketRecord], sessions: List[Dict]) -> Dict[str, Any]:
    """Compute global capture statistics."""
    if not packets:
        return {"total_packets": 0}
    
    total_bytes = sum(p.orig_len for p in packets)
    unique_ips = set()
    unique_macs = set()
    proto_breakdown = defaultdict(lambda: {"packets": 0, "bytes": 0, "transport": ""})
    talker_bytes = defaultdict(int)
    port_counts = Counter()
    flag_counts = defaultdict(int)
    ttl_counts = Counter()
    transport_counts = Counter()
    
    for p in packets:
        unique_ips.add(p.src_ip)
        unique_ips.add(p.dst_ip)
        if p.src_mac:
            unique_macs.add(p.src_mac)
        if p.dst_mac:
            unique_macs.add(p.dst_mac)
        
        proto_breakdown[p.protocol]["packets"] += 1
        proto_breakdown[p.protocol]["bytes"] += p.orig_len
        if not proto_breakdown[p.protocol]["transport"]:
            proto_breakdown[p.protocol]["transport"] = p.transport
        
        talker_bytes[p.src_ip] += p.orig_len
        talker_bytes[p.dst_ip] += p.orig_len
        
        if p.dst_port > 0:
            port_counts[p.dst_port] += 1
        if p.src_port > 0:
            port_counts[p.src_port] += 1
        
        for flag in p.tcp_flags_list:
            flag_counts[flag] += 1
        
        if p.ttl > 0:
            ttl_counts[p.ttl] += 1
        
        transport_counts[p.transport] += 1
    
    unique_ips.discard("")
    unique_macs.discard("")
    
    duration = packets[-1].timestamp - packets[0].timestamp if len(packets) > 1 else 0.0
    
    # Sort and limit
    top_talkers = sorted(talker_bytes.items(), key=lambda x: x[1], reverse=True)[:15]
    top_ports = [
        {"port": p, "count": c, "service": WELL_KNOWN_PORTS.get(p, "")}
        for p, c in port_counts.most_common(15)
    ]
    top_ttls = [{"ttl": t, "count": c} for t, c in ttl_counts.most_common(10)]
    
    protocols = {k: v for k, v in sorted(proto_breakdown.items(), key=lambda x: x[1]["bytes"], reverse=True)}
    
    return {
        "total_packets": len(packets),
        "total_bytes": total_bytes,
        "unique_ips": len(unique_ips),
        "unique_macs": len(unique_macs),
        "total_sessions": len(sessions),
        "duration": round(duration, 3),
        "avg_packet_size": round(total_bytes / len(packets)) if packets else 0,
        "packets_per_second": round(len(packets) / duration, 1) if duration > 0 else 0,
        "bytes_per_second": round(total_bytes / duration, 1) if duration > 0 else 0,
        "protocols": protocols,
        "transport_counts": dict(transport_counts),
        "top_talkers": [{"ip": ip, "bytes": b} for ip, b in top_talkers],
        "top_ports": top_ports,
        "flag_stats": dict(flag_counts),
        "sessions_with_handshake": sum(1 for s in sessions if s.get("has_handshake")),
        "sessions_with_reset": sum(1 for s in sessions if s.get("has_reset")),
        "sessions_with_fin": sum(1 for s in sessions if s.get("has_fin")),
        "first_timestamp": packets[0].timestamp,
        "last_timestamp": packets[-1].timestamp,
    }
