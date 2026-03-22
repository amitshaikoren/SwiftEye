"""
dpkt-based pcap/pcapng reader — used for files >= DPKT_THRESHOLD_BYTES.

dpkt is 5-10x faster than scapy for raw parsing because it avoids scapy's
per-packet Python object construction overhead. The trade-off is that dpkt
gives us less out of the box — no automatic protocol dissection, no TLS layer.

We compensate by:
  - Manually extracting all the same fields scapy extracts
  - Running the same payload signature detection pipeline afterwards
  - Running the same protocol dissectors (dissect_tls, dissect_http, etc.)
    but feeding them raw bytes rather than scapy packet objects. The manual
    fallback paths in each dissector handle this.

The output is identical List[PacketRecord] — the analysis layer never knows
which reader was used.
"""

import hashlib
import logging
import socket
import struct
import time
from pathlib import Path
from typing import List, Optional

from .packet import PacketRecord
from .protocols import resolve_protocol, TCP_FLAG_BITS, detect_protocol_by_payload, DISSECTORS

logger = logging.getLogger("swifteye.parser.dpkt")

# TLS extension type codes needed for JA3/JA4
_TLS_EXT_SNI            = 0x0000
_TLS_EXT_ELLIPTIC       = 0x000a
_TLS_EXT_EC_POINT       = 0x000b
_TLS_EXT_ALPN           = 0x0010
_TLS_EXT_SESSION_TICKET = 0x0023
_TLS_EXT_SUPPORTED_VER  = 0x002b

# Cipher suites to skip in JA3 (GREASE values)
_GREASE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
}

_VER_MAP = {
    0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
    0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}

# All protocol names that can carry TLS and should trigger JA3/JA4 computation.
# Must match the equivalent set in pcap_reader.py.
_TLS_PROTOCOLS = {"TLS", "HTTPS", "HTTPS-ALT", "HTTPS-ALT2", "HTTPS-ALT3"}

PAYLOAD_PREVIEW_SIZE = 128


def read_pcap_dpkt(
    filepath: str,
    max_packets: int = 2_000_000,
) -> List[PacketRecord]:
    """
    Read a pcap/pcapng file using dpkt. Returns List[PacketRecord].
    Raises ImportError if dpkt is not installed.
    Raises ValueError on parse errors.
    """
    try:
        import dpkt
    except ImportError:
        raise ImportError(
            "dpkt is required for large file parsing. "
            "Install it with: pip install dpkt"
        )

    path = Path(filepath)
    packets: List[PacketRecord] = []
    start = time.time()

    with open(path, "rb") as f:
        # Try pcapng first, then pcap
        try:
            reader = dpkt.pcapng.Reader(f)
            link_type = reader.datalink()
        except Exception:
            f.seek(0)
            try:
                reader = dpkt.pcap.Reader(f)
                link_type = reader.datalink()
            except Exception as e:
                raise ValueError(f"Cannot read file with dpkt: {e}")

        for i, (ts, raw) in enumerate(reader):
            if i >= max_packets:
                logger.warning(f"dpkt reader: reached packet limit ({max_packets})")
                break
            rec = _parse_raw(ts, raw, link_type, dpkt)
            if rec is not None:
                packets.append(rec)

    elapsed = time.time() - start
    logger.info(
        f"dpkt: parsed {len(packets)} packets from {path.name} "
        f"in {elapsed:.2f}s"
    )

    packets.sort(key=lambda p: p.timestamp)
    return packets


def _parse_raw(ts: float, raw: bytes, link_type: int, dpkt) -> Optional[PacketRecord]:
    """Parse a raw packet bytes into a PacketRecord."""
    rec = PacketRecord()
    rec.timestamp = float(ts)
    rec.orig_len = len(raw)

    try:
        # ── Layer 2 ───────────────────────────────────────────────────
        eth = None
        if link_type == dpkt.pcap.DLT_EN10MB:
            try:
                eth = dpkt.ethernet.Ethernet(raw)
                if hasattr(eth, "src"):
                    rec.src_mac = _mac(eth.src)
                    rec.dst_mac = _mac(eth.dst)
            except Exception:
                return None
            ip_pkt = eth.data
        elif link_type == dpkt.pcap.DLT_RAW:
            ip_pkt = raw
        elif link_type == 113:  # DLT_LINUX_SLL
            if len(raw) < 16:
                return None
            ip_pkt = raw[16:]
        else:
            ip_pkt = raw

        # ── ARP ───────────────────────────────────────────────────────
        if eth and isinstance(eth.data, dpkt.arp.ARP):
            arp = eth.data
            rec.src_ip  = _ipstr(arp.spa)
            rec.dst_ip  = _ipstr(arp.tpa)
            rec.src_mac = _mac(arp.sha) or rec.src_mac
            rec.dst_mac = _mac(arp.tha) or rec.dst_mac
            rec.transport = "ARP"
            rec.protocol  = "ARP"
            return rec

        # ── Layer 3: IPv4 ─────────────────────────────────────────────
        if isinstance(ip_pkt, (bytes, bytearray)) and len(ip_pkt) >= 1:
            version = (ip_pkt[0] >> 4)
            try:
                if version == 4:
                    ip = dpkt.ip.IP(ip_pkt)
                elif version == 6:
                    ip = dpkt.ip6.IP6(ip_pkt)
                else:
                    return None
            except Exception:
                return None
        elif hasattr(ip_pkt, "data"):
            ip = ip_pkt
        else:
            return None

        if isinstance(ip, dpkt.ip.IP):
            rec.src_ip     = _ipstr(ip.src)
            rec.dst_ip     = _ipstr(ip.dst)
            rec.ip_version = 4
            rec.ttl        = ip.ttl
            rec.ip_proto   = ip.p
            rec.dscp       = ip.tos >> 2
            rec.ip_id      = ip.id
            rec.ip_flags   = ip.off >> 13
            rec.frag_offset = ip.off & 0x1FFF
            l4 = ip.data
        elif isinstance(ip, dpkt.ip6.IP6):
            rec.src_ip     = _ip6str(ip.src)
            rec.dst_ip     = _ip6str(ip.dst)
            rec.ip_version = 6
            rec.ttl        = ip.hlim
            rec.ip_proto   = ip.nxt
            l4 = ip.data
        else:
            return None

        # ── Layer 4: TCP ──────────────────────────────────────────────
        if isinstance(l4, dpkt.tcp.TCP):
            rec.transport    = "TCP"
            rec.src_port     = l4.sport
            rec.dst_port     = l4.dport
            rec.seq_num      = l4.seq
            rec.ack_num      = l4.ack
            rec.window_size  = l4.win
            rec.tcp_data_offset = (l4.off >> 4) * 4 if hasattr(l4, "off") else 20

            flag_val = l4.flags
            rec.tcp_flags = flag_val
            flag_list = [name for name, bit in TCP_FLAG_BITS.items() if flag_val & bit]
            rec.tcp_flags_list = flag_list
            rec.tcp_flags_str  = " ".join(flag_list)

            # TCP options (manual parse)
            rec.tcp_options = _parse_tcp_options(l4)

            payload = bytes(l4.data) if l4.data else b""
            rec.payload_len = len(payload)
            rec.protocol    = resolve_protocol("TCP", l4.sport, l4.dport)
            if payload:
                rec.payload_preview = payload[:PAYLOAD_PREVIEW_SIZE]
                _enrich_from_payload(rec, payload)

        # ── Layer 4: UDP ──────────────────────────────────────────────
        elif isinstance(l4, dpkt.udp.UDP):
            rec.transport = "UDP"
            rec.src_port  = l4.sport
            rec.dst_port  = l4.dport
            payload = bytes(l4.data) if l4.data else b""
            rec.payload_len = len(payload)
            rec.protocol    = resolve_protocol("UDP", l4.sport, l4.dport)
            if payload:
                rec.payload_preview = payload[:PAYLOAD_PREVIEW_SIZE]
                _enrich_from_payload(rec, payload)

        # ── Layer 4: ICMP ─────────────────────────────────────────────
        elif isinstance(l4, dpkt.icmp.ICMP):
            rec.transport  = "ICMP"
            rec.protocol   = "ICMP"
            rec.icmp_type  = l4.type
            rec.icmp_code  = l4.code
        # ── Layer 4: ICMPv6 ───────────────────────────────────────────
        # dpkt exposes ICMPv6 via dpkt.icmp6 if available; fall back to
        # ip.nxt == 58 (IPv6 next-header for ICMPv6) with raw byte parsing.
        elif rec.ip_version == 6 and getattr(rec, 'ip_proto', 0) == 58:
            rec.transport = "ICMPv6"
            rec.protocol  = "ICMPv6"
            try:
                raw = bytes(l4) if not isinstance(l4, bytes) else l4
                if len(raw) >= 2:
                    rec.icmp_type = raw[0]
                    rec.icmp_code = raw[1]
            except Exception:
                pass
        elif rec.ip_version == 6:
            try:
                import dpkt as _dpkt
                if hasattr(_dpkt, 'icmp6') and isinstance(l4, _dpkt.icmp6.ICMP6):
                    rec.transport = "ICMPv6"
                    rec.protocol  = "ICMPv6"
                    rec.icmp_type = l4.type
                    rec.icmp_code = l4.code
                else:
                    rec.transport = "OTHER"
                    rec.protocol  = "OTHER"
            except Exception:
                rec.transport = "OTHER"
                rec.protocol  = "OTHER"
        else:
            rec.transport = "OTHER"
            rec.protocol  = "OTHER"

    except Exception as e:
        logger.debug(f"dpkt parse error: {e}")
        return None

    return rec


def _enrich_from_payload(rec: PacketRecord, payload: bytes):
    """Run protocol detection and dissection on raw payload bytes."""
    port_protocol = rec.protocol
    rec.protocol_by_port = port_protocol if port_protocol != rec.transport else ""

    payload_protocol = None
    if len(payload) >= 4:
        payload_protocol = detect_protocol_by_payload(payload)

    # TLS manual dissection (works on raw bytes)
    if not payload_protocol and len(payload) >= 6 and payload[0] == 0x16:
        payload_protocol = "TLS"

    rec.protocol_by_payload = payload_protocol or ""

    if payload_protocol:
        if rec.protocol == rec.transport:
            rec.protocol = payload_protocol
        elif rec.protocol != payload_protocol:
            rec.protocol_conflict = True
            rec.protocol = payload_protocol

    # ── Raw-byte dissection (dpkt path) ────────────────────────────
    proto = rec.protocol
    extra = {}

    if proto == "DNS":
        extra = _parse_dns_raw(payload)
    elif proto == "FTP":
        extra = _parse_ftp_raw(payload)
    elif proto == "DHCP":
        extra = _parse_dhcp_raw(payload)
    elif proto == "SMB":
        extra = _parse_smb_raw(payload)
    elif proto in DISSECTORS:
        try:
            class _PayloadProxy:
                def __init__(self, data):
                    self._data = data
                def haslayer(self, layer):
                    return layer == "Raw"
                def __getitem__(self, key):
                    if key == "Raw":
                        class _R:
                            load = self._data
                        return _R()
                    raise KeyError(key)
            extra = DISSECTORS[proto](_PayloadProxy(payload))
        except Exception as e:
            logger.warning(f"dpkt dissector error for {proto}: {e}")

    if extra:
        rec.extra = extra

        # JA3/JA4 outside the dissector try/except — a fingerprint failure
        # must never wipe rec.extra (which already has the TLS SNI etc.).
        # Covers all protocol names that can carry TLS.
        if rec.protocol in _TLS_PROTOCOLS:
            try:
                _add_ja_fingerprints(rec, payload)
            except Exception as e:
                logger.warning(f"JA3/JA4 error: {e}")
    elif rec.protocol in _TLS_PROTOCOLS:
        try:
            _add_ja_fingerprints(rec, payload)
        except Exception as e:
            logger.warning(f"JA3/JA4 error: {e}")




# ── Raw-byte protocol parsers (dpkt path) ────────────────────────────────────
# These produce the same field names as the scapy dissectors so the rest of
# the pipeline (sessions, aggregator, frontend) never needs to know which
# path was used.

_QTYPE_NAMES = {1:"A",2:"NS",5:"CNAME",6:"SOA",12:"PTR",15:"MX",
                16:"TXT",28:"AAAA",33:"SRV",255:"ANY"}
_RCODE_NAMES = {0:"NOERROR",1:"FORMERR",2:"SERVFAIL",3:"NXDOMAIN",
                4:"NOTIMP",5:"REFUSED"}


def _dns_decode_name(data: bytes, off: int, depth: int = 0):
    """Decode a DNS name from wire format, following pointers."""
    if depth > 10:
        return "", off
    labels = []
    while off < len(data):
        length = data[off]
        if length == 0:
            off += 1
            break
        elif (length & 0xC0) == 0xC0:  # pointer
            if off + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            name, _ = _dns_decode_name(data, ptr, depth + 1)
            labels.append(name)
            off += 2
            break
        else:
            off += 1
            if off + length > len(data):
                break
            labels.append(data[off:off + length].decode("ascii", errors="replace"))
            off += length
    return ".".join(labels), off


def _parse_dns_raw(payload: bytes) -> dict:
    """Parse a DNS wire-format message. Works on both UDP and TCP (with length prefix)."""
    try:
        # TCP DNS has a 2-byte length prefix
        data = payload
        if len(data) < 12:
            return {}
        dns_id   = (data[0] << 8) | data[1]
        flags    = (data[2] << 8) | data[3]
        qr       = (flags >> 15) & 1     # 0=query, 1=response
        opcode   = (flags >> 11) & 0xF
        rcode    = flags & 0xF
        qdcount  = (data[4] << 8) | data[5]
        ancount  = (data[6] << 8) | data[7]

        info = {
            "dns_id":     dns_id,
            "dns_qr":     "response" if qr else "query",
            "dns_opcode": opcode,
            "dns_rcode":  rcode,
        }

        off = 12
        # Question section
        if qdcount > 0 and off < len(data):
            name, off = _dns_decode_name(data, off)
            if off + 4 <= len(data):
                qtype  = (data[off] << 8) | data[off + 1]
                off += 4
                info["dns_query"] = name.rstrip(".")
                info["dns_qtype"] = qtype

        # Answer section
        if ancount > 0:
            answers = []
            for _ in range(min(ancount, 10)):
                if off >= len(data):
                    break
                _, off = _dns_decode_name(data, off)  # name (skip)
                if off + 10 > len(data):
                    break
                rtype  = (data[off] << 8) | data[off + 1]
                rdlen  = (data[off + 8] << 8) | data[off + 9]
                off += 10
                rdata_end = off + rdlen
                if rdata_end > len(data):
                    break
                rdata = data[off:rdata_end]
                if rtype == 1 and rdlen == 4:        # A
                    answers.append(".".join(str(b) for b in rdata))
                elif rtype == 28 and rdlen == 16:    # AAAA
                    answers.append(":".join(f"{rdata[i]:02x}{rdata[i+1]:02x}"
                                           for i in range(0, 16, 2)))
                elif rtype in (5, 2, 12, 15):        # CNAME/NS/PTR/MX
                    cname, _ = _dns_decode_name(data, off if rtype != 15 else off + 2)
                    answers.append(cname.rstrip("."))
                elif rtype == 16:                    # TXT
                    txt_off = off
                    parts = []
                    while txt_off < rdata_end:
                        tlen = data[txt_off]; txt_off += 1
                        parts.append(data[txt_off:txt_off + tlen].decode("utf-8", errors="replace"))
                        txt_off += tlen
                    answers.append(" ".join(parts))
                off = rdata_end
            if answers:
                info["dns_answers"] = answers

        return info
    except Exception:
        return {}


def _parse_ftp_raw(payload: bytes) -> dict:
    """Extract FTP command/response fields from raw bytes."""
    try:
        line = payload.split(b"\r\n")[0].split(b"\n")[0].decode("utf-8", errors="replace").strip()
        info = {}
        if line[:3].isdigit():
            info["ftp_response_code"] = int(line[:3])
            info["ftp_response_msg"]  = line[4:] if len(line) > 4 else ""
        else:
            parts = line.split(None, 1)
            cmd = parts[0].upper() if parts else ""
            arg = parts[1] if len(parts) > 1 else ""
            info["ftp_command"] = cmd
            if cmd == "USER":
                info["ftp_user"] = arg
            elif cmd == "PASS":
                info["ftp_password"] = arg
            elif cmd in ("RETR", "STOR", "DELE", "RNFR", "RNTO", "MKD", "CWD"):
                info["ftp_filename"] = arg
        return info
    except Exception:
        return {}


def _parse_dhcp_raw(payload: bytes) -> dict:
    """Parse DHCP/BOOTP fixed header and options."""
    try:
        if len(payload) < 240:
            return {}
        msg_type_code = payload[0]   # 1=BOOTREQUEST, 2=BOOTREPLY
        # Offered/client IP
        yiaddr = ".".join(str(payload[16 + i]) for i in range(4))  # your IP
        ciaddr = ".".join(str(payload[12 + i]) for i in range(4))  # client IP
        chaddr = ":".join(f"{payload[28 + i]:02x}" for i in range(6))

        info = {
            "dhcp_msg_type_code": msg_type_code,
            "dhcp_offered_ip":    yiaddr if yiaddr != "0.0.0.0" else None,
            "dhcp_client_ip":     ciaddr if ciaddr != "0.0.0.0" else None,
            "dhcp_client_mac":    chaddr,
        }

        # Parse options (magic cookie at offset 236)
        if payload[236:240] != b"\x63\x82\x53\x63":
            return {k: v for k, v in info.items() if v is not None}

        off = 240
        msg_type_names = {1:"Discover",2:"Offer",3:"Request",4:"Decline",
                          5:"ACK",6:"NAK",7:"Release",8:"Inform"}
        while off < len(payload):
            opt = payload[off]; off += 1
            if opt == 255: break   # END
            if opt == 0:   continue  # PAD
            if off >= len(payload): break
            opt_len = payload[off]; off += 1
            if off + opt_len > len(payload): break
            opt_data = payload[off:off + opt_len]; off += opt_len
            if opt == 53:   # DHCP Message Type
                info["dhcp_msg_type"] = msg_type_names.get(opt_data[0], str(opt_data[0]))
            elif opt == 12: # Hostname
                info["dhcp_hostname"] = opt_data.decode("utf-8", errors="replace")
            elif opt == 51: # Lease time
                info["dhcp_lease_time"] = int.from_bytes(opt_data, "big")
            elif opt == 54: # Server identifier
                info["dhcp_server"] = ".".join(str(b) for b in opt_data[:4])

        return {k: v for k, v in info.items() if v is not None}
    except Exception:
        return {}


def _parse_smb_raw(payload: bytes) -> dict:
    """Extract SMB version, command, and tree/file info from raw bytes."""
    try:
        info = {}
        # NBT session header (4 bytes) may prefix SMB over TCP
        off = 0
        if len(payload) > 4 and payload[0] == 0x00:
            off = 4  # skip NBT session header

        if off + 4 > len(payload):
            return {}

        sig = payload[off:off + 4]
        if sig == b"\xffSMB":
            info["smb_version"] = "SMB1"
            if off + 5 <= len(payload):
                cmd = payload[off + 4]
                cmds = {0x72:"Negotiate",0x73:"Session Setup",0x75:"Tree Connect",
                        0xa2:"NT Create",0x2e:"Read",0x2f:"Write",
                        0x24:"LockingX",0x04:"Close"}
                info["smb_command"] = cmds.get(cmd, f"0x{cmd:02x}")
        elif sig == b"\xfeSMB":
            info["smb_version"] = "SMB2"
            if off + 16 <= len(payload):
                cmd = (payload[off + 12] << 8) | payload[off + 13]
                cmds = {0x0000:"Negotiate",0x0001:"Session Setup",0x0003:"Tree Connect",
                        0x0004:"Tree Disconnect",0x0005:"Create",0x0006:"Close",
                        0x0008:"Read",0x0009:"Write",0x000e:"IOCTL",0x000f:"Cancel"}
                info["smb_command"] = cmds.get(cmd, f"0x{cmd:04x}")
        elif sig == b"\xfdSMB":
            info["smb_version"] = "SMB3"

        return info
    except Exception:
        return {}

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
            return None  # Not TLS

        # TLS record layer: type(1) version(2) length(2)
        rec_type = data[0]
        if rec_type != 0x16:
            return None

        off = 5  # skip TLS record header
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
                    # TLS 1.3 negotiated version
                    if len(ed) >= 2:
                        for i in range(1, len(ed), 2):
                            if i + 1 < len(ed):
                                v = (ed[i] << 8) | ed[i + 1]
                                if v not in _GREASE and v > negotiated_version:
                                    negotiated_version = v

                off += el

        # ── JA3 ───────────────────────────────────────────────────────
        # Format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
        ja3_str = (
            f"{tls_version},"
            f"{'-'.join(str(c) for c in ciphers)},"
            f"{'-'.join(str(e) for e in ext_types)},"
            f"{'-'.join(str(c) for c in curves)},"
            f"{'-'.join(str(p) for p in point_formats)}"
        )
        ja3 = hashlib.md5(ja3_str.encode()).hexdigest()

        # ── JA4 ───────────────────────────────────────────────────────
        # Format: q(d|i)(2-char version)(2-char cipher count)(2-char ext count)(ALPN)(12-char cipher hash)_(12-char ext hash)
        # q = QUIC? always 't' for TCP
        # d|i = SNI present (d=domain) or absent (i=IP/no SNI)
        ver_map_ja4 = {
            0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3",
        }
        ver_str = ver_map_ja4.get(negotiated_version, "00")
        sni_char = "d" if sni else "i"
        cipher_count = f"{min(len(ciphers), 99):02d}"
        ext_count = f"{min(len(ext_types), 99):02d}"
        alpn_str = alpn_list[0][:2] if alpn_list else "00"

        # Sorted cipher hash (exclude GREASE)
        sorted_ciphers = sorted(ciphers)
        cipher_hash = hashlib.sha256(
            ",".join(f"{c:04x}" for c in sorted_ciphers).encode()
        ).hexdigest()[:12]

        # Sorted extension hash (exclude SNI=0 and ALPN=16)
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
        logger.debug(f"JA3/JA4 parse error: {e}")
        return None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mac(b: bytes) -> str:
    try:
        return ":".join(f"{x:02x}" for x in b)
    except Exception:
        return ""


def _ipstr(b: bytes) -> str:
    try:
        return ".".join(str(x) for x in b)
    except Exception:
        return ""


def _ip6str(b: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, b)
    except Exception:
        return ""


def _parse_tcp_options(tcp_seg) -> list:
    """Parse TCP options from a dpkt TCP segment."""
    opts = []
    try:
        import dpkt
        for opt in dpkt.tcp.parse_opts(tcp_seg.opts):
            kind, data = opt
            if kind == dpkt.tcp.TCP_OPT_MSS and len(data) == 2:
                opts.append({"kind": "MSS", "value": struct.unpack("!H", data)[0]})
            elif kind == dpkt.tcp.TCP_OPT_WSCALE and len(data) == 1:
                opts.append({"kind": "WScale", "value": data[0]})
            elif kind == dpkt.tcp.TCP_OPT_SACKOK:
                opts.append({"kind": "SAckOK", "value": True})
            elif kind == dpkt.tcp.TCP_OPT_TIMESTAMP and len(data) == 8:
                tsval, tsecr = struct.unpack("!II", data)
                opts.append({"kind": "Timestamp", "tsval": tsval, "tsecr": tsecr})
    except Exception:
        pass
    return opts
