"""
Packet serialization helpers for the storage layer.

These functions convert PacketRecord fields into API-friendly dicts.
Extracted from workspaces.network.store.py to be shared by all StorageBackend implementations.
"""

import math
from collections import Counter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from workspaces.network.parser.packet import PacketRecord


def _payload_hexdump(data: bytes) -> str:
    """
    Format raw bytes as a unified Wireshark-style hex dump.
    Each row: offset  hex-bytes (padded to 16)  ascii
    Example:  0000  16 03 01 00 f1 01 00 00  .......
    Returned as a single string with newline-separated rows.
    The frontend renders this in a single <pre> block — no column splitting needed.
    """
    if not data:
        return ""
    rows = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"{i:04x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(rows)


def _payload_hex(data: bytes) -> str:
    """Alias for _payload_hexdump — kept for backward compatibility."""
    return _payload_hexdump(data)


def _payload_ascii(data: bytes) -> str:
    """ASCII is now embedded in the hex dump rows; no longer served separately."""
    return ""


def _payload_entropy(data: bytes) -> dict:
    """
    Compute Shannon entropy of payload bytes and classify it.

    Returns {value, label, min_bytes} or empty dict if too few bytes.
    Minimum 16 bytes for a meaningful reading.
    """
    if not data or len(data) < 16:
        return {}
    counts = Counter(data)
    length = len(data)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    entropy = round(entropy, 2)

    if entropy < 1.0:
        label = "Structured/repetitive"
    elif entropy < 3.5:
        label = "Low entropy (structured binary)"
    elif entropy < 5.0:
        label = "Text/markup"
    elif entropy < 6.5:
        label = "Mixed/encoded"
    elif entropy < 7.5:
        label = "High entropy (compressed)"
    else:
        label = "Likely encrypted/compressed"

    return {"value": entropy, "label": label, "byte_count": length}


def serialize_packet(pkt: "PacketRecord") -> dict:
    """Convert a PacketRecord to the API dict shape for session detail packets."""
    return {
        "timestamp": pkt.timestamp,
        "src_ip": pkt.src_ip,
        "dst_ip": pkt.dst_ip,
        "src_port": pkt.src_port,
        "dst_port": pkt.dst_port,
        "protocol": pkt.protocol,
        "transport": pkt.transport,
        "length": pkt.orig_len,
        "payload_len": pkt.payload_len,
        "ttl": pkt.ttl,
        "tcp_flags_str": pkt.tcp_flags_str,
        "tcp_flags_list": pkt.tcp_flags_list,
        "seq_num": pkt.seq_num,
        "ack_num": pkt.ack_num,
        "window_size": pkt.window_size,
        "tcp_options": pkt.tcp_options,
        "tcp_data_offset": pkt.tcp_data_offset,
        "urg_ptr": pkt.urg_ptr,
        # ICMP
        "icmp_type": pkt.icmp_type,
        "icmp_code": pkt.icmp_code,
        # IP header fields
        "ip_version": pkt.ip_version,
        "dscp": pkt.dscp,
        "ecn": pkt.ecn,
        "ip_id": pkt.ip_id,
        "ip_flags": pkt.ip_flags,
        "frag_offset": pkt.frag_offset,
        "ip_checksum": pkt.ip_checksum,
        "ip6_flow_label": pkt.ip6_flow_label,
        "tcp_checksum": pkt.tcp_checksum,
        "extra": pkt.extra,
        "payload_hex": _payload_hex(pkt.payload_preview),
        "payload_ascii": _payload_ascii(pkt.payload_preview),
        "payload_bytes": pkt.payload_preview.hex() if pkt.payload_preview else "",
        "payload_entropy": _payload_entropy(pkt.payload_preview),
    }
