"""
Protocol constants — now centralised in backend/constants.py.

This file re-exports everything for backwards compatibility with
any code that still imports from parser.protocols.ports directly.
All new code should import from constants instead.
"""
from constants import (
    WELL_KNOWN_PORTS,
    PROTOCOL_COLORS,
    TCP_FLAG_NAMES,
    TCP_FLAG_BITS,
    ICMP_TYPES,
    ICMP_DEST_UNREACH_CODES,
    CIPHER_SUITES,
)

__all__ = [
    "WELL_KNOWN_PORTS", "PROTOCOL_COLORS",
    "TCP_FLAG_NAMES", "TCP_FLAG_BITS",
    "ICMP_TYPES", "ICMP_DEST_UNREACH_CODES",
    "CIPHER_SUITES",
]
