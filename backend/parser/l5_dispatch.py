"""
L5 (application layer) enrichment for SwiftEye's unified dpkt reader.

Called after dpkt has parsed all L2/L3/L4 fields into a PacketRecord.
Constructs the appropriate L5 object from raw payload bytes and dispatches
to the registered protocol dissector.

By default, dissectors receive a lightweight _L5Proxy (haslayer("Raw") +
pkt["Raw"].load) — no scapy overhead. Dissectors that need a real scapy
object declare it via @register_dissector("PROTO", scapy_layer=SomeClass).
This module reads DISSECTOR_SCAPY_LAYERS from the registry and constructs
the declared scapy object only for those protocols.

Protocols with no L5 payload (ARP, ICMP, ICMPv6) bypass this module entirely.
They are handled in dpkt_reader._parse_raw().
"""

import hashlib
import logging
import struct
from typing import Optional

from .packet import PacketRecord
from .protocols import DISSECTORS, DISSECTOR_SCAPY_LAYERS, detect_protocol_by_payload

logger = logging.getLogger("swifteye.parser.l5")

# Protocol names that carry TLS
_TLS_PROTOCOLS = {"TLS", "HTTPS", "HTTPS-ALT", "HTTPS-ALT2", "HTTPS-ALT3"}

PAYLOAD_PREVIEW_SIZE = 128


class _L5Proxy:
    """
    Lightweight substitute for scapy Raw(load=payload).

    Most dissectors only call pkt.haslayer("Raw") and read pkt["Raw"].load.
    Constructing a real scapy Raw object has significant overhead (metaclass,
    Packet.__init__, layer binding) that is completely unnecessary for this
    simple interface. This proxy provides the same API at near-zero cost.

    Benchmarked: ~50ns vs ~4µs for scapy Raw(load=payload) — 80x faster.
    """
    __slots__ = ('_load',)

    def __init__(self, data: bytes):
        self._load = data

    def haslayer(self, layer) -> bool:
        return layer == "Raw"

    def __getitem__(self, key):
        if key == "Raw":
            return self
        raise KeyError(key)

    @property
    def load(self) -> bytes:
        return self._load

# ── TLS JA3/JA4 constants ───────────────────────────────────────────────────

_TLS_EXT_SNI            = 0x0000
_TLS_EXT_ELLIPTIC       = 0x000a
_TLS_EXT_EC_POINT       = 0x000b
_TLS_EXT_ALPN           = 0x0010
_TLS_EXT_SESSION_TICKET = 0x0023
_TLS_EXT_SUPPORTED_VER  = 0x002b

_GREASE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
}

_VER_MAP = {
    0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
    0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}


def enrich_l5(rec: PacketRecord, payload: bytes) -> None:
    """
    Detect application protocol, construct scapy L5 object, run dissector.
    Mutates rec in place. Called for TCP and UDP packets only.
    ARP and ICMP bypass this — they are handled in dpkt_reader._parse_raw().
    """
    if not payload:
        return

    # Store payload preview for hex/ascii view in SessionDetail
    if not rec.payload_preview:
        rec.payload_preview = payload[:PAYLOAD_PREVIEW_SIZE]
    rec.payload_len = max(rec.payload_len, len(payload))

    proto = rec.protocol
    transport = rec.transport

    # ── Protocol detection ────────────────────────────────────────────────
    rec.protocol_by_port = proto if proto != transport else ""

    payload_protocol: Optional[str] = None
    if len(payload) >= 4:
        payload_protocol = detect_protocol_by_payload(payload)

    # TLS fallback: byte marker (0x16 = TLS record type)
    if not payload_protocol and len(payload) >= 6 and payload[0] == 0x16:
        payload_protocol = "TLS"

    rec.protocol_by_payload = payload_protocol or ""

    if payload_protocol:
        if proto == transport:
            rec.protocol = payload_protocol
            proto = payload_protocol
            rec.protocol_confidence = "payload"
        elif proto == payload_protocol or _protocols_compatible(proto, payload_protocol):
            rec.protocol_confidence = "port+payload"
        else:
            rec.protocol_conflict = True
            rec.protocol = payload_protocol
            proto = payload_protocol
            rec.protocol_confidence = "payload"
    elif proto != transport:
        rec.protocol_confidence = "port"

    # ── Strip transport-layer quirks ─────────────────────────────────────
    # TCP DNS has a 2-byte length prefix before the DNS message.
    # Strip it here so dissectors receive clean wire format.
    clean_payload = payload
    scapy_layer_cls = DISSECTOR_SCAPY_LAYERS.get(proto)
    if scapy_layer_cls is not None and transport == "TCP" and len(payload) > 2:
        # DNS-wire protocols (DNS, mDNS, LLMNR) have a 2-byte TCP length prefix
        if scapy_layer_cls.__name__ == "DNS":
            clean_payload = payload[2:]

    # ── Construct L5 packet object ────────────────────────────────────────
    # Dissectors that declared scapy_layer= get a real scapy object.
    # Everything else gets _L5Proxy — 80x cheaper, same haslayer("Raw") API.
    if scapy_layer_cls is not None:
        try:
            scapy_pkt = scapy_layer_cls(clean_payload)
        except Exception:
            scapy_pkt = _L5Proxy(clean_payload)
    else:
        scapy_pkt = _L5Proxy(clean_payload)

    # ── Run dissector ─────────────────────────────────────────────────────
    if proto in DISSECTORS:
        try:
            extra = DISSECTORS[proto](scapy_pkt)
            if extra:
                rec.extra = extra
        except Exception as e:
            logger.warning("Dissector error for %s: %s", proto, e)

    # ── JA3/JA4 fingerprints for TLS ─────────────────────────────────────
    # Run on original payload (not clean_payload) — JA3/JA4 parser expects
    # the TLS record header at offset 0.
    if proto in _TLS_PROTOCOLS:
        try:
            _add_ja_fingerprints(rec, payload)
        except Exception as e:
            logger.warning("JA3/JA4 error: %s", e)


def _protocols_compatible(a: str, b: str) -> bool:
    """Check if two protocol names refer to the same protocol family."""
    COMPAT = {
        frozenset({"HTTPS", "TLS"}),
        frozenset({"HTTP", "HTTP-ALT"}),
        frozenset({"HTTP", "HTTP-ALT2"}),
        frozenset({"HTTPS", "HTTPS-ALT"}),
    }
    return frozenset({a, b}) in COMPAT


# ── JA3/JA4 fingerprinting ──────────────────────────────────────────────────
# Moved here from dpkt_reader.py to avoid circular imports.

def _add_ja_fingerprints(rec: PacketRecord, payload: bytes):
    """Compute JA3 and JA4 from a TLS ClientHello payload and add to rec.extra."""
    result = _parse_client_hello(payload)
    if not result:
        return
    rec.extra = rec.extra or {}
    if result.get("ja3"):
        rec.extra["ja3"] = result["ja3"]
    if result.get("ja3_string"):
        rec.extra["ja3_string"] = result["ja3_string"]
    if result.get("ja4"):
        rec.extra["ja4"] = result["ja4"]
    if result.get("sni") and not rec.extra.get("tls_sni"):
        rec.extra["tls_sni"] = result["sni"]


def _parse_client_hello(data: bytes) -> Optional[dict]:
    """
    Parse a TLS ClientHello from raw bytes and return JA3/JA4 data.
    Returns None if not a ClientHello.
    """
    try:
        if len(data) < 10 or data[0] != 0x16:
            return None

        off = 5  # skip TLS record header (type, version, length)
        if off >= len(data):
            return None

        # Handshake layer: type(1) length(3)
        if data[off] != 0x01:
            return None  # Not ClientHello
        off += 4

        # ClientHello: client_version(2) random(32) session_id_len(1)
        if off + 35 >= len(data):
            return None
        tls_version = (data[off] << 8) | data[off + 1]
        off += 2 + 32  # skip version + random

        sid_len = data[off]; off += 1 + sid_len  # skip session id

        # Cipher suites
        if off + 2 > len(data):
            return None
        cs_len = (data[off] << 8) | data[off + 1]; off += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            if off + i + 1 >= len(data):
                break
            c = (data[off + i] << 8) | data[off + i + 1]
            if c not in _GREASE:
                ciphers.append(c)
        off += cs_len

        # Compression methods
        if off >= len(data):
            return None
        comp_len = data[off]; off += 1 + comp_len

        # Extensions
        ext_types = []
        curves = []
        point_formats = []
        alpn_list = []
        sni = None
        negotiated_version = tls_version

        if off + 2 <= len(data):
            ext_total = (data[off] << 8) | data[off + 1]; off += 2
            ext_end = off + ext_total
            while off + 4 <= ext_end and off + 4 <= len(data):
                et = (data[off] << 8) | data[off + 1]
                el = (data[off + 2] << 8) | data[off + 3]
                off += 4
                if et not in _GREASE:
                    ext_types.append(et)

                ed = data[off:off + el]

                if et == _TLS_EXT_SNI and len(ed) > 5:
                    sni_len = (ed[3] << 8) | ed[4]
                    sni = ed[5:5 + sni_len].decode(errors="replace")

                elif et == _TLS_EXT_ELLIPTIC and len(ed) >= 2:
                    curves_len = (ed[0] << 8) | ed[1]
                    for i in range(2, 2 + curves_len, 2):
                        if i + 1 < len(ed):
                            c = (ed[i] << 8) | ed[i + 1]
                            if c not in _GREASE:
                                curves.append(c)

                elif et == _TLS_EXT_EC_POINT and len(ed) >= 1:
                    for b in ed[1:1 + ed[0]]:
                        point_formats.append(b)

                elif et == _TLS_EXT_ALPN and len(ed) >= 4:
                    a_off = 2
                    while a_off + 1 < len(ed):
                        a_len = ed[a_off]; a_off += 1
                        alpn_list.append(ed[a_off:a_off + a_len].decode(errors="replace"))
                        a_off += a_len

                elif et == _TLS_EXT_SUPPORTED_VER:
                    if len(ed) >= 2:
                        for i in range(1, len(ed), 2):
                            if i + 1 < len(ed):
                                v = (ed[i] << 8) | ed[i + 1]
                                if v not in _GREASE and v > negotiated_version:
                                    negotiated_version = v

                off += el

        # ── JA3 ───────────────────────────────────────────────────────
        ja3_str = (
            f"{tls_version},"
            f"{'-'.join(str(c) for c in ciphers)},"
            f"{'-'.join(str(e) for e in ext_types)},"
            f"{'-'.join(str(c) for c in curves)},"
            f"{'-'.join(str(p) for p in point_formats)}"
        )
        ja3 = hashlib.md5(ja3_str.encode()).hexdigest()

        # ── JA4 ───────────────────────────────────────────────────────
        ver_map_ja4 = {
            0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3",
        }
        ver_str = ver_map_ja4.get(negotiated_version, "00")
        sni_char = "d" if sni else "i"
        cipher_count = f"{min(len(ciphers), 99):02d}"
        ext_count = f"{min(len(ext_types), 99):02d}"
        alpn_str = alpn_list[0][:2] if alpn_list else "00"

        sorted_ciphers = sorted(ciphers)
        cipher_hash = hashlib.sha256(
            ",".join(f"{c:04x}" for c in sorted_ciphers).encode()
        ).hexdigest()[:12]

        sorted_exts = sorted(e for e in ext_types if e not in (0x0000, 0x0010))
        ext_hash = hashlib.sha256(
            ",".join(f"{e:04x}" for e in sorted_exts).encode()
        ).hexdigest()[:12]

        ja4 = f"t{sni_char}{ver_str}{cipher_count}{ext_count}{alpn_str}_{cipher_hash}_{ext_hash}"

        return {
            "ja3": ja3,
            "ja3_string": ja3_str,
            "ja4": ja4,
            "sni": sni,
            "tls_version": tls_version,
        }

    except Exception as e:
        logger.debug("JA3/JA4 parse error: %s", e)
        return None
