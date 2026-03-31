"""
Pcap/pcapng reader using scapy.

Designed to be swappable — the analysis layer only sees List[PacketRecord].
A future dpkt-based reader would implement the same read_pcap() interface.
"""

import logging
import time
from pathlib import Path
from typing import List, Optional, Callable

from scapy.all import (
    PcapReader, PcapNgReader,
    Ether, IP, IPv6, TCP, UDP, ICMP, ARP,
    Raw, Dot1Q, CookedLinux,
)
from scapy.layers.dns import DNS

from .packet import PacketRecord
from .protocols import resolve_protocol, DISSECTORS, TCP_FLAG_BITS, detect_protocol_by_payload

# Optional scapy layers — imported once at module load, guarded so missing
# extras (e.g. scapy-tls not installed) degrade gracefully at runtime.
_TLS_LAYER = None
_HTTP_LAYER = None
try:
    from scapy.layers.tls.record import TLS as _TLS_LAYER  # type: ignore
except Exception:
    pass
try:
    from scapy.layers.http import HTTP as _HTTP_LAYER  # type: ignore
except Exception:
    pass

# ICMPv6 classes imported once — used in the IPv6 branch of _parse_packet
_ICMPV6_CLASSES = ()
try:
    from scapy.layers.inet6 import (  # type: ignore
        ICMPv6EchoRequest, ICMPv6EchoReply,
        ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RA, ICMPv6ND_RS,
        ICMPv6DestUnreach, ICMPv6TimeExceeded, ICMPv6PacketTooBig,
    )
    _ICMPV6_CLASSES = (
        ICMPv6EchoRequest, ICMPv6EchoReply,
        ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RA, ICMPv6ND_RS,
        ICMPv6DestUnreach, ICMPv6TimeExceeded, ICMPv6PacketTooBig,
    )
except Exception:
    pass

# _add_ja_fingerprints from dpkt_reader — imported once, used in TLS branch
_add_ja_fingerprints = None
try:
    from .dpkt_reader import _add_ja_fingerprints  # type: ignore
except Exception:
    pass

logger = logging.getLogger("swifteye.parser")

MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB hard limit
MAX_PACKETS = 2_000_000
PAYLOAD_PREVIEW_SIZE = 128
PROGRESS_CALLBACK_INTERVAL = 10000

# Scapy is used for all files up to this size — it gives full protocol dissection
# (DNS, TLS, HTTP, etc.) via its layer system. dpkt is only a fallback for very
# large files where scapy's memory usage would be prohibitive.
#
# The old threshold was 20MB which caused dissection failures on most real captures
# (hostnames not resolved, TLS data missing, etc.) because dpkt dissectors don't
# have parity with scapy dissectors yet.
#
# Roadmap: improve dpkt dissectors to match scapy output, then lower this threshold.
DPKT_THRESHOLD = 500 * 1024 * 1024  # Use dpkt only for files >= 500 MB


def read_pcap(
    filepath: str,
    max_packets: int = MAX_PACKETS,
    progress_callback: Optional[Callable[[int, float], None]] = None,
) -> List[PacketRecord]:
    """
    Read a pcap/pcapng file and return normalized PacketRecords.

    Files < 500MB use scapy (full protocol dissection: DNS, TLS, HTTP, etc.).
    Files >= 500MB use dpkt (faster, lower memory — dissection is partial).
    Falls back to scapy if dpkt fails or is not installed.

    Args:
        filepath: Path to the pcap file
        max_packets: Maximum number of packets to parse
        progress_callback: Optional callback(packet_count, elapsed_seconds)

    Returns:
        List of PacketRecord objects, sorted by timestamp
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    file_size = path.stat().st_size
    if file_size > MAX_FILE_SIZE:
        raise ValueError(f"File too large: {file_size / 1024 / 1024:.1f}MB (max {MAX_FILE_SIZE // 1024 // 1024}MB)")

    if file_size == 0:
        raise ValueError("File is empty")

    if file_size >= DPKT_THRESHOLD:
        try:
            from .dpkt_reader import read_pcap_dpkt
            logger.info(f"Using dpkt reader for very large file ({file_size / 1024 / 1024:.1f}MB)")
            logger.warning("dpkt path: DNS/TLS/HTTP dissection is partial. Hostnames may not resolve.")
            return read_pcap_dpkt(str(path), max_packets=max_packets)
        except ImportError:
            logger.warning("dpkt not installed, falling back to scapy")
        except Exception as e:
            logger.warning(f"dpkt reader failed ({e}), falling back to scapy")

    logger.info(f"Parsing {file_size / 1024 / 1024:.1f}MB with scapy")
    return _read_scapy(str(path), max_packets, progress_callback)


def _read_scapy(
    filepath: str,
    max_packets: int = MAX_PACKETS,
    progress_callback: Optional[Callable[[int, float], None]] = None,
) -> List[PacketRecord]:
    """Scapy-based reader. Used for all files < 500MB."""
    path = Path(filepath)
    packets: List[PacketRecord] = []
    start_time = time.time()

    # Try pcapng first, fall back to pcap
    reader = None
    try:
        reader = PcapNgReader(str(path))
    except Exception:
        try:
            reader = PcapReader(str(path))
        except Exception as e:
            raise ValueError(f"Cannot read file: {e}")

    try:
        for i, pkt in enumerate(reader):
            if i >= max_packets:
                logger.warning(f"Reached packet limit ({max_packets}), stopping")
                break

            rec = _parse_packet(pkt)
            if rec is not None:
                packets.append(rec)

            if progress_callback and i % PROGRESS_CALLBACK_INTERVAL == 0:
                progress_callback(i, time.time() - start_time)
    finally:
        reader.close()

    elapsed = time.time() - start_time
    logger.info(f"scapy: parsed {len(packets)} packets from {path.name} in {elapsed:.2f}s")

    packets.sort(key=lambda p: p.timestamp)
    return packets


def _parse_packet(pkt) -> Optional[PacketRecord]:
    """Parse a single scapy packet into a PacketRecord."""
    rec = PacketRecord()
    
    # Timestamp
    rec.timestamp = float(pkt.time)
    rec.orig_len = len(pkt)
    
    # ── Layer 2 ──────────────────────────────────────────────────────
    if pkt.haslayer(Ether):
        rec.src_mac = pkt[Ether].src or ""
        rec.dst_mac = pkt[Ether].dst or ""
    
    # ── ARP ──────────────────────────────────────────────────────────
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        rec.src_ip = arp.psrc or ""
        rec.dst_ip = arp.pdst or ""
        rec.src_mac = rec.src_mac or (arp.hwsrc or "")
        rec.dst_mac = rec.dst_mac or (arp.hwdst or "")
        rec.transport = "ARP"
        rec.protocol = "ARP"
        _ARP_OPCODES = {1: "request", 2: "reply", 3: "RARP request", 4: "RARP reply"}
        opcode = arp.op or 0
        rec.extra["arp_opcode"] = opcode
        rec.extra["arp_opcode_name"] = _ARP_OPCODES.get(opcode, f"opcode_{opcode}")
        rec.extra["arp_src_mac"] = arp.hwsrc or ""
        rec.extra["arp_dst_mac"] = arp.hwdst or ""
        rec.extra["arp_src_ip"] = arp.psrc or ""
        rec.extra["arp_dst_ip"] = arp.pdst or ""
        if rec.dst_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            rec.extra["arp_broadcast"] = True
        return rec
    
    # ── Layer 3: IPv4 ────────────────────────────────────────────────
    if pkt.haslayer(IP):
        ip = pkt[IP]
        rec.src_ip = ip.src or ""
        rec.dst_ip = ip.dst or ""
        rec.ip_version = 4
        rec.ttl = ip.ttl
        rec.ip_proto = ip.proto
        rec.dscp = ip.tos >> 2
        rec.ecn = ip.tos & 0x03
        rec.ip_id = ip.id
        rec.ip_flags = int(ip.flags)
        rec.frag_offset = ip.frag
        try: rec.ip_checksum = ip.chksum or 0
        except Exception: pass
    
    # ── Layer 3: IPv6 ────────────────────────────────────────────────
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        rec.src_ip = ip6.src or ""
        rec.dst_ip = ip6.dst or ""
        rec.ip_version = 6
        rec.ttl = ip6.hlim
        rec.ip_proto = ip6.nh
        # Traffic class: upper 6 bits = DSCP, lower 2 bits = ECN (same as IPv4 ToS)
        try:
            tc = ip6.tc or 0
            rec.dscp = tc >> 2
            rec.ecn = tc & 0x03
            rec.ip6_flow_label = ip6.fl or 0
        except Exception:
            pass
    
    else:
        # No IP layer — skip
        return None
    
    # ── Layer 4: TCP ─────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        rec.transport = "TCP"
        rec.src_port = tcp.sport
        rec.dst_port = tcp.dport
        rec.seq_num = tcp.seq
        rec.ack_num = tcp.ack
        rec.window_size = tcp.window
        rec.tcp_data_offset = tcp.dataofs * 4 if tcp.dataofs else 20
        rec.urg_ptr = tcp.urgptr
        try: rec.tcp_checksum = tcp.chksum or 0
        except Exception: pass
        
        # TCP flags
        flag_val = int(tcp.flags)
        rec.tcp_flags = flag_val
        flag_list = []
        for name, bit in TCP_FLAG_BITS.items():
            if flag_val & bit:
                flag_list.append(name)
        rec.tcp_flags_list = flag_list
        rec.tcp_flags_str = " ".join(flag_list)
        
        # TCP options
        tcp_opts = []
        try:
            for opt_name, opt_val in tcp.options:
                opt_entry = {"kind": opt_name}
                if opt_name == "MSS":
                    opt_entry["value"] = opt_val
                elif opt_name == "WScale":
                    opt_entry["value"] = opt_val
                elif opt_name == "SAckOK":
                    opt_entry["value"] = True
                elif opt_name == "Timestamp":
                    if isinstance(opt_val, tuple) and len(opt_val) == 2:
                        opt_entry["tsval"] = opt_val[0]
                        opt_entry["tsecr"] = opt_val[1]
                elif opt_name == "SAck":
                    opt_entry["value"] = str(opt_val)
                else:
                    opt_entry["value"] = str(opt_val) if opt_val else None
                tcp_opts.append(opt_entry)
        except Exception:
            pass
        rec.tcp_options = tcp_opts
        
        # Payload size + extract raw bytes for JA3/JA4 fingerprinting.
        # We capture these here, before any dissectors run, because scapy's TLS
        # layer (when installed) consumes the Raw layer — pkt.haslayer(Raw) will
        # be False later in the function even for TLS packets.
        _tcp_raw_payload = b""
        if pkt.haslayer(Raw):
            _tcp_raw_payload = bytes(pkt[Raw].load)
            rec.payload_len = len(_tcp_raw_payload)
        elif hasattr(pkt, "lastlayer") and hasattr(pkt.lastlayer(), "load"):
            # When scapy TLS layer is present, Raw is gone but we can try lastlayer
            try:
                _tcp_raw_payload = bytes(pkt.lastlayer().load)
                rec.payload_len = len(_tcp_raw_payload)
            except Exception:
                pass
        
        # Store first 128 bytes for payload preview (hex+ascii view in SessionDetail)
        if _tcp_raw_payload:
            rec.payload_preview = _tcp_raw_payload[:PAYLOAD_PREVIEW_SIZE]

        # Resolve protocol
        rec.protocol = resolve_protocol("TCP", tcp.sport, tcp.dport)
    
    # ── Layer 4: UDP ─────────────────────────────────────────────────
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        rec.transport = "UDP"
        rec.src_port = udp.sport
        rec.dst_port = udp.dport
        
        _udp_raw = b""
        if pkt.haslayer(Raw):
            _udp_raw = bytes(pkt[Raw].load)
            rec.payload_len = len(_udp_raw)
        if _udp_raw:
            rec.payload_preview = _udp_raw[:PAYLOAD_PREVIEW_SIZE]

        rec.protocol = resolve_protocol("UDP", udp.sport, udp.dport)
    
    # ── Layer 4: ICMP ────────────────────────────────────────────────
    elif pkt.haslayer(ICMP):
        icmp_pkt = pkt[ICMP]
        rec.transport = "ICMP"
        rec.protocol = "ICMP"
        rec.icmp_type = icmp_pkt.type
        rec.icmp_code = icmp_pkt.code
    # ── Layer 4: ICMPv6 ──────────────────────────────────────────────
    elif rec.ip_version == 6:
        if _ICMPV6_CLASSES:
            for cls in _ICMPV6_CLASSES:
                if pkt.haslayer(cls):
                    layer = pkt[cls]
                    rec.transport = "ICMPv6"
                    rec.protocol = "ICMPv6"
                    rec.icmp_type = getattr(layer, "type", 0)
                    rec.icmp_code = getattr(layer, "code", 0)
                    break
    
    else:
        rec.transport = "OTHER"
        rec.protocol = "OTHER"
    
    # ── Protocol dissectors ──────────────────────────────────────────
    if rec.protocol in DISSECTORS:
        try:
            rec.extra = DISSECTORS[rec.protocol](pkt)
        except Exception as e:
            logger.warning(f"Dissector error for {rec.protocol}: {e}")
    
    # ── Payload-based protocol detection ─────────────────────────────
    # Three-tier detection:
    #   1. Scapy's own layers (most reliable, if available)
    #   2. Payload signature registry (manual matchers)
    #   3. Port-based resolution was already done above
    #
    # We always run payload detection, even if port gave us a protocol,
    # to detect conflicts (e.g. TLS on port 80).
    
    port_protocol = rec.protocol  # what port resolution said
    rec.protocol_by_port = port_protocol if port_protocol != rec.transport else ""
    payload_protocol = None
    
    if pkt.haslayer(Raw):
        raw_payload = bytes(pkt[Raw].load)

        # Tier 1: scapy layers (module-level imports, no per-packet import overhead)
        if _TLS_LAYER is not None and pkt.haslayer(_TLS_LAYER):
            payload_protocol = "TLS"
        if not payload_protocol and _HTTP_LAYER is not None and pkt.haslayer(_HTTP_LAYER):
            payload_protocol = "HTTP"
        
        # Tier 2: signature registry
        if not payload_protocol and len(raw_payload) >= 4:
            payload_protocol = detect_protocol_by_payload(raw_payload)
    
    rec.protocol_by_payload = payload_protocol or ""
    
    # Resolve final protocol + detect conflicts
    if payload_protocol:
        if rec.protocol == rec.transport:
            # Port didn't identify anything — use payload result
            rec.protocol = payload_protocol
            rec.protocol_confidence = "payload"
        elif rec.protocol == payload_protocol or _protocols_compatible(rec.protocol, payload_protocol):
            # Port and payload agree (or are compatible, e.g. HTTPS ≈ TLS)
            rec.protocol_confidence = "port+payload"
        else:
            # Conflict: port says one thing, payload says another
            # Payload wins (it's looking at actual data), but flag the conflict
            rec.protocol_conflict = True
            rec.protocol_confidence = "payload"
            rec.protocol = payload_protocol
    elif rec.protocol != rec.transport:
        rec.protocol_confidence = "port"
    
    # Run dissector for the final protocol if we haven't yet
    if rec.protocol != port_protocol and rec.protocol in DISSECTORS and not rec.extra:
        try:
            rec.extra = DISSECTORS[rec.protocol](pkt)
        except Exception as e:
            logger.warning(f"Dissector error for {rec.protocol}: {e}")
    
    # Special case: DNS over UDP (scapy detects DNS layer regardless of port)
    if pkt.haslayer(DNS) and rec.protocol != "DNS":
        rec.protocol = "DNS"
        rec.protocol_confidence = "scapy_layer"
        if "DNS" in DISSECTORS:
            try:
                rec.extra = DISSECTORS["DNS"](pkt)
            except Exception:
                pass

    # ── JA3/JA4 fingerprints for TLS ClientHello ────────────────────
    # Covers all protocol names that can carry TLS, not just the two main ones.
    # Uses _tcp_raw_payload captured before dissectors ran, because scapy's TLS
    # layer (when installed) consumes the Raw layer and pkt.haslayer(Raw) is False.
    _TLS_PROTOCOLS = {"TLS", "HTTPS", "HTTPS-ALT", "HTTPS-ALT2", "HTTPS-ALT3"}
    if rec.transport == "TCP" and rec.protocol in _TLS_PROTOCOLS and _add_ja_fingerprints is not None:
        try:
            # _tcp_raw_payload is set in the TCP branch above.
            _raw_for_ja = _tcp_raw_payload  # noqa: F821
            if not _raw_for_ja and pkt.haslayer(Raw):
                _raw_for_ja = bytes(pkt[Raw].load)
            # Also try to get raw bytes from scapy TLS layer if present
            if not _raw_for_ja and _TLS_LAYER is not None and pkt.haslayer(_TLS_LAYER):
                _raw_for_ja = bytes(pkt[_TLS_LAYER].original or b"")
            if _raw_for_ja:
                _add_ja_fingerprints(rec, _raw_for_ja)
        except Exception:
            pass

    return rec


def _protocols_compatible(a: str, b: str) -> bool:
    """Check if two protocol names refer to the same thing."""
    COMPAT = {
        frozenset({"HTTPS", "TLS"}),
        frozenset({"HTTP", "HTTP-ALT"}),
        frozenset({"HTTP", "HTTP-ALT2"}),
        frozenset({"HTTPS", "HTTPS-ALT"}),
    }
    return frozenset({a, b}) in COMPAT
