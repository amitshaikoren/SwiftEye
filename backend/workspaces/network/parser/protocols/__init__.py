"""
Protocol registry package for SwiftEye.

This package provides:
  - Port → protocol mapping (ports.py)
  - Protocol dissectors (dissect_*.py)
  - Payload signature matchers (signatures.py)
  - Resolution and detection functions

To add a new protocol:
  1. Add port mapping to ports.py WELL_KNOWN_PORTS
  2. Add color to ports.py PROTOCOL_COLORS
  3. Add payload signature to signatures.py (for non-standard port detection)
  4. Add dissector in a new dissect_*.py file (for metadata extraction)
"""

from typing import Callable, Dict, Any, List, Optional, Tuple

# ── Registries ───────────────────────────────────────────────────────────
# These are populated by the dissector and signature files when they import
# register_dissector / register_payload_signature from this module.

DISSECTORS: Dict[str, Callable] = {}
DISSECTOR_SCAPY_LAYERS: Dict[str, type] = {}  # protocol → scapy class (e.g. DNS)
PAYLOAD_SIGNATURES: List[Tuple[int, str, Callable]] = []


def register_dissector(protocol: str, scapy_layer: Optional[type] = None):
    """
    Decorator to register a protocol dissector.

    Args:
        protocol: Protocol name (e.g. "DNS", "HTTP")
        scapy_layer: Optional scapy class this dissector needs (e.g. DNS).
                     If set, l5_dispatch constructs that scapy object from
                     raw payload bytes before calling the dissector.
                     If None (default), the dissector receives a lightweight
                     proxy with haslayer("Raw") / pkt["Raw"].load — no scapy
                     overhead. Most dissectors should NOT set this.
    """
    def wrapper(func: Callable):
        DISSECTORS[protocol] = func
        if scapy_layer is not None:
            DISSECTOR_SCAPY_LAYERS[protocol] = scapy_layer
        return func
    return wrapper


def register_payload_signature(protocol: str, priority: int = 50):
    """Decorator to register a payload signature matcher."""
    def wrapper(func: Callable):
        PAYLOAD_SIGNATURES.append((priority, protocol, func))
        PAYLOAD_SIGNATURES.sort(key=lambda x: x[0])
        return func
    return wrapper


def detect_protocol_by_payload(payload: bytes) -> Optional[str]:
    """Run all registered payload signatures. Returns first match or None."""
    for _, protocol, matcher in PAYLOAD_SIGNATURES:
        try:
            if matcher(payload):
                return protocol
        except Exception:
            continue
    return None


# ── Re-exports from ports.py ─────────────────────────────────────────────
from .ports import (
    WELL_KNOWN_PORTS, PROTOCOL_COLORS, TCP_FLAG_NAMES, TCP_FLAG_BITS,
    ICMP_TYPES, ICMP_DEST_UNREACH_CODES, CIPHER_SUITES,
)


def resolve_protocol(transport: str, sport: int, dport: int) -> str:
    """Resolve application-layer protocol from transport + ports."""
    if dport in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[dport]
    if sport in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[sport]
    return transport


def get_protocol_color(protocol: str) -> str:
    """Get display color for a protocol."""
    return PROTOCOL_COLORS.get(protocol, PROTOCOL_COLORS["OTHER"])


# ── Auto-import dissectors and signatures ────────────────────────────────
# Importing these modules causes their @register_dissector and
# @register_payload_signature decorators to fire, populating the registries.
from . import dissect_dns      # noqa: F401
from . import dissect_http     # noqa: F401
from . import dissect_tls      # noqa: F401
from . import dissect_icmp     # noqa: F401  (ICMPv4 + ICMPv6)
from . import dissect_ssh      # noqa: F401
from . import dissect_ftp      # noqa: F401
from . import dissect_dhcp     # noqa: F401
from . import dissect_smb      # noqa: F401
from . import dissect_kerberos # noqa: F401
from . import dissect_ldap     # noqa: F401
from . import dissect_smtp     # noqa: F401
from . import dissect_mdns     # noqa: F401
from . import dissect_ssdp     # noqa: F401
from . import dissect_llmnr    # noqa: F401
from . import dissect_dcerpc   # noqa: F401
from . import dissect_quic     # noqa: F401
from . import signatures       # noqa: F401
