from .pcap_reader import read_pcap, MAX_FILE_SIZE, MAX_PACKETS
from .packet import PacketRecord
from .protocols import (
    resolve_protocol,
    register_dissector,
    register_payload_signature,
    detect_protocol_by_payload,
    DISSECTORS,
    PAYLOAD_SIGNATURES,
)
# Re-export from the central constants module for backwards compatibility
from constants import WELL_KNOWN_PORTS, PROTOCOL_COLORS

__all__ = [
    "read_pcap",
    "PacketRecord",
    "WELL_KNOWN_PORTS",
    "PROTOCOL_COLORS",
    "resolve_protocol",
    "register_dissector",
    "register_payload_signature",
    "detect_protocol_by_payload",
    "DISSECTORS",
    "PAYLOAD_SIGNATURES",
    "MAX_FILE_SIZE",
    "MAX_PACKETS",
]
