"""
Normalized packet representation for SwiftEye.

All parsed packets are converted to PacketRecord for uniform processing.
This is the boundary between parser and analysis layers.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass(slots=True)
class PacketRecord:
    """Single normalized packet. Designed for fast DataFrame conversion."""
    # Timing
    timestamp: float = 0.0
    
    # Layer 2
    src_mac: str = ""
    dst_mac: str = ""
    
    # Layer 3
    src_ip: str = ""
    dst_ip: str = ""
    ip_version: int = 4
    ttl: int = 0
    ip_proto: int = 0       # raw IP protocol number
    dscp: int = 0
    ecn: int = 0            # ECN bits (bottom 2 bits of ToS/TC): 0=non-ECT,1=ECT1,2=ECT0,3=CE
    ip_id: int = 0
    ip_flags: int = 0
    frag_offset: int = 0
    ip_checksum: int = 0    # IPv4 header checksum (0 if not available / IPv6)
    tcp_checksum: int = 0   # TCP checksum (0 if not available)
    ip6_flow_label: int = 0  # IPv6 flow label (0 for IPv4 or unset)
    
    # Layer 4
    src_port: int = 0
    dst_port: int = 0
    transport: str = ""     # "TCP", "UDP", "ICMP", etc.
    protocol: str = ""      # resolved app protocol: "HTTP", "DNS", etc.
    
    # Protocol detection metadata
    protocol_by_port: str = ""       # what port-based resolution said
    protocol_by_payload: str = ""    # what payload inspection said
    protocol_confidence: str = ""    # "port", "payload", "scapy_layer", "port+payload"
    protocol_conflict: bool = False  # True if port and payload disagree
    
    # TCP-specific
    tcp_flags: int = 0          # raw flag byte
    tcp_flags_str: str = ""     # "SYN ACK" etc.
    tcp_flags_list: List[str] = field(default_factory=list)
    seq_num: int = 0
    ack_num: int = 0
    window_size: int = 0
    tcp_options: List[Dict[str, Any]] = field(default_factory=list)
    tcp_data_offset: int = 0
    urg_ptr: int = 0
    
    # ICMP
    icmp_type: int = -1
    icmp_code: int = -1
    
    # Sizes
    orig_len: int = 0
    payload_len: int = 0

    # First 128 bytes of application payload — stored for payload preview in SessionDetail.
    # None if the packet has no payload or payload_len == 0.
    # Stored as bytes to keep it compact; serialised to hex+ascii on demand by the API.
    payload_preview: bytes = b""
    
    # Protocol-specific extra fields (from dissectors)
    extra: Dict[str, Any] = field(default_factory=dict)

    # Cached session key — computed once on first access, never re-sorted
    _session_key_cache: str = field(default="", repr=False, compare=False)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for DataFrame construction. Flattens extras."""
        d = {
            "timestamp": self.timestamp,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "ip_version": self.ip_version,
            "ttl": self.ttl,
            "ip_proto": self.ip_proto,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "transport": self.transport,
            "protocol": self.protocol,
            "tcp_flags": self.tcp_flags,
            "tcp_flags_str": self.tcp_flags_str,
            "seq_num": self.seq_num,
            "ack_num": self.ack_num,
            "window_size": self.window_size,
            "icmp_type": self.icmp_type,
            "icmp_code": self.icmp_code,
            "orig_len": self.orig_len,
            "payload_len": self.payload_len,
        }
        return d
    
    @property
    def session_key(self) -> str:
        """Canonical session key (sorted IPs+ports for bidirectional matching).
        Cached after first access — src/dst/ports/transport never change post-parse."""
        if self._session_key_cache:
            return self._session_key_cache
        if self.src_ip <= self.dst_ip:
            ip_a, ip_b = self.src_ip, self.dst_ip
        else:
            ip_a, ip_b = self.dst_ip, self.src_ip
        if self.src_port <= self.dst_port:
            p_a, p_b = self.src_port, self.dst_port
        else:
            p_a, p_b = self.dst_port, self.src_port
        key = f"{ip_a}|{ip_b}|{p_a}|{p_b}|{self.transport}"
        object.__setattr__(self, '_session_key_cache', key)
        return key
    
    @property
    def is_private_src(self) -> bool:
        return _is_private(self.src_ip)
    
    @property
    def is_private_dst(self) -> bool:
        return _is_private(self.dst_ip)


def _is_private(ip: str) -> bool:
    """Check if IPv4 address is in private range."""
    if not ip or ":" in ip:
        return False
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return False
        a, b = parts[0], parts[1]
        return (
            a == 10 or
            (a == 172 and 16 <= b <= 31) or
            (a == 192 and b == 168) or
            a == 127
        )
    except (ValueError, IndexError):
        return False
