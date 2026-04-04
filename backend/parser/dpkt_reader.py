"""
dpkt-based pcap/pcapng reader — L2/L3/L4 parsing only.

Since v0.17.0 this is the sole packet reader for all file sizes.
L5 enrichment (protocol detection, dissector dispatch, JA3/JA4) is handled
by l5_dispatch.enrich_l5(), called at the end of _parse_raw() for TCP/UDP.

ARP and ICMP are fully handled here (no L5 payload to dispatch).
"""

import logging
import socket
import struct
import time
from pathlib import Path
from typing import List, Optional

import dpkt

from scapy.packet import Raw as _ScapyRaw

from .packet import PacketRecord
from .protocols import resolve_protocol, TCP_FLAG_BITS, DISSECTORS
from .l5_dispatch import enrich_l5

logger = logging.getLogger("swifteye.parser.dpkt")

_ARP_OPCODES = {1: "request", 2: "reply", 3: "RARP request", 4: "RARP reply"}

# Precomputed TCP flag lookup: flag_byte → list of flag name strings.
_TCP_FLAGS_TABLE: list = [None] * 256
for _fv in range(256):
    _TCP_FLAGS_TABLE[_fv] = [name for name, bit in TCP_FLAG_BITS.items() if _fv & bit]


def read_pcap_dpkt(
    filepath: str,
    max_packets: int = 2_000_000,
    start_offset: int = 0,
) -> List[PacketRecord]:
    """
    Read a pcap/pcapng file using dpkt. Returns List[PacketRecord].

    Args:
        filepath: Path to the pcap/pcapng file
        max_packets: Maximum number of packets to parse
        start_offset: Byte offset to seek to after reading the global header.
                      Used by parallel_reader to split work across processes.
    """
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

        # For parallel chunking: seek to the start offset after the reader
        # has consumed the global header. dpkt's __next__ reads from current
        # file position, so seeking to a known packet boundary works.
        if start_offset > 0:
            f.seek(start_offset)

        for i, (ts, raw) in enumerate(reader):
            if i >= max_packets:
                logger.warning("dpkt reader: reached packet limit (%d)", max_packets)
                break
            rec = _parse_raw(ts, raw, link_type)
            if rec is not None:
                packets.append(rec)

    elapsed = time.time() - start
    logger.info(
        "dpkt: parsed %d packets from %s in %.2fs",
        len(packets), path.name, elapsed,
    )

    packets.sort(key=lambda p: p.timestamp)
    return packets


def _parse_raw(ts: float, raw: bytes, link_type: int) -> Optional[PacketRecord]:
    """Parse raw packet bytes into a PacketRecord (L2/L3/L4 only)."""
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

        # ── ARP ──────────────��────────────────────────────────────────
        if eth and isinstance(eth.data, dpkt.arp.ARP):
            arp = eth.data
            rec.src_ip  = _ipstr(arp.spa)
            rec.dst_ip  = _ipstr(arp.tpa)
            rec.src_mac = _mac(arp.sha) or rec.src_mac
            rec.dst_mac = _mac(arp.tha) or rec.dst_mac
            rec.transport = "ARP"
            rec.protocol  = "ARP"
            arp_op = getattr(arp, 'op', 0)
            rec.extra = {
                "arp_opcode":      arp_op,
                "arp_opcode_name": _ARP_OPCODES.get(arp_op, f"opcode_{arp_op}"),
                "arp_src_mac":     _mac(arp.sha),
                "arp_dst_mac":     _mac(arp.tha),
                "arp_src_ip":      _ipstr(arp.spa),
                "arp_dst_ip":      _ipstr(arp.tpa),
            }
            if _mac(arp.tha) in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                rec.extra["arp_broadcast"] = True
            return rec

        # ── Layer 3: IPv4 / IPv6 ─────────────���───────────────────────
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
            rec.src_ip      = _ipstr(ip.src)
            rec.dst_ip      = _ipstr(ip.dst)
            rec.ip_version  = 4
            rec.ttl         = ip.ttl
            rec.ip_proto    = ip.p
            rec.dscp        = ip.tos >> 2
            rec.ecn         = ip.tos & 0x03
            rec.ip_id       = ip.id
            rec.ip_flags    = ip.off >> 13
            rec.frag_offset = ip.off & 0x1FFF
            rec.ip_checksum = ip.sum
            l4 = ip.data
        elif isinstance(ip, dpkt.ip6.IP6):
            rec.src_ip     = _ip6str(ip.src)
            rec.dst_ip     = _ip6str(ip.dst)
            rec.ip_version = 6
            rec.ttl        = ip.hlim
            rec.ip_proto   = ip.nxt
            tc = getattr(ip, 'fc', 0) or 0
            rec.dscp = tc >> 2
            rec.ecn  = tc & 0x03
            rec.ip6_flow_label = getattr(ip, 'flow', 0)
            l4 = ip.data
        else:
            return None

        # ── Layer 4: TCP ──────────────────────────────────────────────
        if isinstance(l4, dpkt.tcp.TCP):
            rec.transport       = "TCP"
            rec.src_port        = l4.sport
            rec.dst_port        = l4.dport
            rec.seq_num         = l4.seq
            rec.ack_num         = l4.ack
            rec.window_size     = l4.win
            rec.tcp_data_offset = (l4.off >> 4) * 4 if hasattr(l4, "off") else 20
            rec.urg_ptr         = getattr(l4, 'urp', 0)
            rec.tcp_checksum    = getattr(l4, 'sum', 0)

            flag_val = l4.flags
            rec.tcp_flags = flag_val
            flag_list = _TCP_FLAGS_TABLE[flag_val & 0xFF]
            rec.tcp_flags_list = flag_list
            rec.tcp_flags_str  = " ".join(flag_list)

            rec.tcp_options = _parse_tcp_options(l4)

            payload = bytes(l4.data) if l4.data else b""
            rec.payload_len = len(payload)
            rec.protocol    = resolve_protocol("TCP", l4.sport, l4.dport)

            if payload:
                enrich_l5(rec, payload)

        # ── Layer 4: UDP ───────────���──────────────────────────────────
        elif isinstance(l4, dpkt.udp.UDP):
            rec.transport = "UDP"
            rec.src_port  = l4.sport
            rec.dst_port  = l4.dport
            payload = bytes(l4.data) if l4.data else b""
            rec.payload_len = len(payload)
            rec.protocol    = resolve_protocol("UDP", l4.sport, l4.dport)

            if payload:
                enrich_l5(rec, payload)

        # ── Layer 4: ICMP ─────────────────────────────────────────────
        elif isinstance(l4, dpkt.icmp.ICMP):
            rec.transport  = "ICMP"
            rec.protocol   = "ICMP"
            rec.icmp_type  = l4.type
            rec.icmp_code  = l4.code
            try:
                icmp_raw = bytes(l4)
                if "ICMP" in DISSECTORS:
                    extra = DISSECTORS["ICMP"](_ScapyRaw(load=icmp_raw))
                    if extra:
                        rec.extra = extra
            except Exception:
                pass

        # ── Layer 4: ICMPv6 ──────────────���────────────────────────────
        elif rec.ip_version == 6 and getattr(rec, 'ip_proto', 0) == 58:
            rec.transport = "ICMPv6"
            rec.protocol  = "ICMPv6"
            try:
                raw_l4 = bytes(l4) if not isinstance(l4, bytes) else l4
                if len(raw_l4) >= 2:
                    rec.icmp_type = raw_l4[0]
                    rec.icmp_code = raw_l4[1]
            except Exception:
                pass
        elif rec.ip_version == 6:
            try:
                if hasattr(dpkt, 'icmp6') and isinstance(l4, dpkt.icmp6.ICMP6):
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
        logger.debug("dpkt parse error: %s", e)
        return None

    return rec


# ── Helpers ───────────────��───────────────────────────────────────────────────

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
        for opt in dpkt.tcp.parse_opts(tcp_seg.opts):
            kind, data = opt
            if kind == dpkt.tcp.TCP_OPT_MSS and len(data) == 2:
                opts.append({"kind": "MSS", "value": struct.unpack("!H", data)[0]})
            elif kind == dpkt.tcp.TCP_OPT_WSCALE and len(data) == 1:
                opts.append({"kind": "WScale", "value": data[0]})
            elif kind == dpkt.tcp.TCP_OPT_SACKOK:
                opts.append({"kind": "SAckOK", "value": True})
            elif kind == dpkt.tcp.TCP_OPT_SACK:
                opts.append({"kind": "SAck", "value": data.hex()})
            elif kind == dpkt.tcp.TCP_OPT_TIMESTAMP and len(data) == 8:
                tsval, tsecr = struct.unpack("!II", data)
                opts.append({"kind": "Timestamp", "tsval": tsval, "tsecr": tsecr})
    except Exception:
        pass
    return opts
