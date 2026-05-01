"""
Multiprocessing wrapper for SwiftEye's dpkt reader.

Architecture:
  1. Pre-scan: read only 16-byte pcap packet headers → collect byte offsets (fast, I/O only)
  2. Split offsets into N equal chunks (N = CPU count, capped at 8)
  3. Spawn N workers via 'spawn' context (Windows + Linux compatible)
  4. Each worker: open file, seek to its byte range, parse packets directly via struct reads
  5. Merge results, sort by timestamp

Workers use explicit byte-range reads (not dpkt.pcap.Reader + seek) because dpkt's
Reader may have buffered past the seek point, causing all workers to read from the
beginning of the file. Direct struct parsing is also faster (no pcapng probe overhead).

pcapng: falls back to single-threaded read_pcap_dpkt. pcapng block format
is variable-width and complex to pre-scan. See roadmap item pcapng-battle-test.

Windows note: 'spawn' context means each worker imports Python fresh (~0.3s
overhead). Acceptable for files large enough to warrant multiprocessing (> 50 MB).

use_parallel=False disables multiprocessing entirely — useful for debugging
or when the system has multiprocessing issues.
"""

import logging
import multiprocessing
import os
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple

from .packet import PacketRecord
from .dpkt_reader import _parse_raw, read_pcap_dpkt

logger = logging.getLogger("swifteye.parser.parallel")

_MAX_WORKERS = 8
_MIN_PACKETS_FOR_PARALLEL = 10_000

# L4 protocol number → name (for prescan; L7 detection requires full parse)
_L4_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
_ETHERTYPE_IPv4 = 0x0800
_ETHERTYPE_IPv6 = 0x86DD
_ETHERTYPE_VLAN = 0x8100


def _prescan_pcap(filepath: str) -> Optional[Tuple[int, bool, List[int]]]:
    """
    Read only 16-byte per-packet headers from a pcap file to collect byte offsets.
    Returns (link_type, little_endian, [offset_of_each_packet_header]) or None if
    the file is not a valid pcap (e.g. it is pcapng).

    Does NOT read any packet data — pure I/O over metadata only.
    """
    MAGIC_LE = 0xa1b2c3d4
    MAGIC_BE = 0xd4c3b2a1
    MAGIC_NS_LE = 0xa1b23c4d
    MAGIC_NS_BE = 0x4d3cb2a1

    try:
        with open(filepath, "rb") as f:
            global_hdr = f.read(24)
            if len(global_hdr) < 24:
                return None
            magic = struct.unpack_from("<I", global_hdr, 0)[0]
            if magic in (MAGIC_LE, MAGIC_NS_LE):
                little_endian = True
            elif magic in (MAGIC_BE, MAGIC_NS_BE):
                little_endian = False
            else:
                return None  # pcapng or unknown

            order = "<" if little_endian else ">"
            link_type = struct.unpack_from(f"{order}I", global_hdr, 20)[0]

            offsets: List[int] = []
            while True:
                pos = f.tell()
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break
                incl_len = struct.unpack_from(f"{order}I", pkt_hdr, 8)[0]
                offsets.append(pos)
                f.seek(incl_len, 1)

        return link_type, little_endian, offsets
    except Exception as e:
        logger.debug("pcap pre-scan failed: %s", e)
        return None


def _worker_prescan_chunk(args: tuple) -> dict:
    """
    L3-only prescan worker. Runs in a spawned child process.
    Reads every packet in [start_offset, end_offset), extracts src/dst IP and
    L4 protocol — no scapy, no dpkt, no PacketRecord objects.

    Returns a compact stats dict for merging in the main process.
    """
    filepath, start_offset, end_offset, link_type, little_endian = args
    order = "<" if little_endian else ">"

    packet_count = 0
    ts_first: Optional[float] = None
    ts_last: Optional[float] = None
    ips: set = set()
    pairs: dict = {}   # frozenset({src_ip, dst_ip}) → int
    protocols: dict = {}  # proto_name → int

    with open(filepath, "rb") as f:
        f.seek(start_offset)
        while True:
            pos = f.tell()
            if pos >= end_offset:
                break
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{order}IIII", hdr)
            raw = f.read(incl_len)
            if len(raw) < incl_len:
                break

            ts = ts_sec + ts_usec * 1e-6
            packet_count += 1
            if ts_first is None or ts < ts_first:
                ts_first = ts
            if ts_last is None or ts > ts_last:
                ts_last = ts

            # Only Ethernet frames carry IP in a predictable position.
            if link_type != 1 or len(raw) < 14:
                continue

            ethertype = struct.unpack_from(">H", raw, 12)[0]
            ip_offset = 14
            # Single VLAN tag (802.1Q)
            if ethertype == _ETHERTYPE_VLAN and len(raw) >= 18:
                ethertype = struct.unpack_from(">H", raw, 16)[0]
                ip_offset = 18

            if ethertype == _ETHERTYPE_IPv4 and len(raw) >= ip_offset + 20:
                ip_hdr = raw[ip_offset: ip_offset + 20]
                ip_proto = ip_hdr[9]
                src_ip = socket.inet_ntoa(ip_hdr[12:16])
                dst_ip = socket.inet_ntoa(ip_hdr[16:20])
                proto_name = _L4_PROTO_NAMES.get(ip_proto, "OTHER")

            elif ethertype == _ETHERTYPE_IPv6 and len(raw) >= ip_offset + 40:
                ip_hdr = raw[ip_offset: ip_offset + 40]
                next_hdr = ip_hdr[6]
                try:
                    src_ip = socket.inet_ntop(socket.AF_INET6, ip_hdr[8:24])
                    dst_ip = socket.inet_ntop(socket.AF_INET6, ip_hdr[24:40])
                except (OSError, AttributeError):
                    # Fallback for platforms where inet_ntop is unavailable
                    src_ip = ':'.join(
                        f'{ip_hdr[8 + i * 2]:02x}{ip_hdr[9 + i * 2]:02x}' for i in range(8)
                    )
                    dst_ip = ':'.join(
                        f'{ip_hdr[24 + i * 2]:02x}{ip_hdr[25 + i * 2]:02x}' for i in range(8)
                    )
                proto_name = _L4_PROTO_NAMES.get(next_hdr, "OTHER")

            else:
                continue

            ips.add(src_ip)
            ips.add(dst_ip)
            key = frozenset({src_ip, dst_ip})
            pairs[key] = pairs.get(key, 0) + 1
            protocols[proto_name] = protocols.get(proto_name, 0) + 1

    return {
        "packet_count": packet_count,
        "ts_first":     ts_first,
        "ts_last":      ts_last,
        "ips":          ips,
        "pairs":        pairs,
        "protocols":    protocols,
    }


def prescan_pcap_parallel(filepath: str) -> Optional[Dict]:
    """
    Fast L3-only parallel scan of a pcap file.

    Runs _worker_prescan_chunk across N workers. Each worker reads every packet
    in its byte range but only parses up to the IP header — no scapy, no dpkt,
    no PacketRecord creation. Approximately 5–10× faster than a full parse.

    Returns:
        {
          "packet_count":    int,
          "ts_first":        float | None,   # Unix timestamp
          "ts_last":         float | None,
          "node_count":      int,            # unique IPs
          "edge_count":      int,            # unique IP pairs
          "protocols":       {str: int},     # {"TCP": N, "UDP": N, ...}
          "top_ips":         [{"ip": str, "packets": int}],  # top 50 by traffic
        }
    Returns None if the file is not a valid legacy pcap (e.g. pcapng).
    """
    scan = _prescan_pcap(filepath)
    if scan is None:
        return None

    link_type, little_endian, offsets = scan
    n_packets = len(offsets)
    if n_packets == 0:
        return {
            "packet_count": 0, "ts_first": None, "ts_last": None,
            "node_count": 0, "edge_count": 0, "protocols": {}, "top_ips": [],
        }

    try:
        n_workers = min(multiprocessing.cpu_count(), _MAX_WORKERS)
    except Exception:
        n_workers = 1

    file_size = os.path.getsize(filepath)
    chunk_size = max(1, n_packets // n_workers)
    chunks: List[List[int]] = [offsets[i: i + chunk_size] for i in range(0, n_packets, chunk_size)]

    worker_args = []
    for i, chunk in enumerate(chunks):
        if not chunk:
            continue
        start = chunk[0]
        end = chunks[i + 1][0] if (i + 1 < len(chunks) and chunks[i + 1]) else file_size
        worker_args.append((filepath, start, end, link_type, little_endian))

    t0 = time.time()
    ctx = multiprocessing.get_context("spawn")
    try:
        with ctx.Pool(len(worker_args)) as pool:
            results: List[dict] = pool.map(_worker_prescan_chunk, worker_args)
    except Exception as e:
        logger.warning("Prescan parallel failed (%s), falling back to single-threaded", e)
        results = [_worker_prescan_chunk((filepath, offsets[0], file_size, link_type, little_endian))]

    logger.info("Prescan: %d packets scanned in %.2fs", n_packets, time.time() - t0)

    # Merge worker results
    total_packets = sum(r["packet_count"] for r in results)
    ts_first = min((r["ts_first"] for r in results if r["ts_first"] is not None), default=None)
    ts_last  = max((r["ts_last"]  for r in results if r["ts_last"]  is not None), default=None)

    all_ips: set = set()
    all_pairs: dict = {}
    all_protocols: dict = {}

    for r in results:
        all_ips.update(r["ips"])
        for k, v in r["pairs"].items():
            all_pairs[k] = all_pairs.get(k, 0) + v
        for k, v in r["protocols"].items():
            all_protocols[k] = all_protocols.get(k, 0) + v

    # Top IPs by total packets (sum of all pairs they participate in)
    ip_traffic: dict = {}
    for pair, count in all_pairs.items():
        for ip in pair:
            ip_traffic[ip] = ip_traffic.get(ip, 0) + count
    top_ips = [
        {"ip": ip, "packets": cnt}
        for ip, cnt in sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)[:50]
    ]

    return {
        "packet_count": total_packets,
        "ts_first":     ts_first,
        "ts_last":      ts_last,
        "node_count":   len(all_ips),
        "edge_count":   len(all_pairs),
        "protocols":    all_protocols,
        "top_ips":      top_ips,
    }


def _worker_parse_chunk(args: tuple) -> List[PacketRecord]:
    """
    Worker function. Runs in a spawned child process.
    Reads packets from start_offset to end_offset (byte positions) using
    direct struct reads — does NOT use dpkt.pcap.Reader to avoid buffering
    issues that cause the reader to ignore seeks.

    ts_start / ts_end: if set, packets outside this Unix-timestamp window are
    skipped *before* _parse_raw is called, saving significant CPU for narrow
    time-range loads on large captures.
    """
    filepath, start_offset, end_offset, link_type, little_endian, max_pkts, ts_start, ts_end = args
    order = "<" if little_endian else ">"
    packets: List[PacketRecord] = []
    t0 = time.time()

    with open(filepath, "rb") as f:
        f.seek(start_offset)
        while True:
            if len(packets) >= max_pkts:
                break
            pos = f.tell()
            if pos >= end_offset:
                break
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{order}IIII", hdr)
            ts = ts_sec + ts_usec * 1e-6

            # Time filter: skip packet data without parsing if outside window.
            if ts_start is not None and ts < ts_start:
                f.seek(incl_len, 1)
                continue
            if ts_end is not None and ts > ts_end:
                f.seek(incl_len, 1)
                continue

            raw = f.read(incl_len)
            if len(raw) < incl_len:
                break
            rec = _parse_raw(ts, raw, link_type)
            if rec is not None:
                packets.append(rec)

    elapsed = time.time() - t0
    logger.info(
        "parallel chunk [%d–%d]: parsed %d packets in %.2fs",
        start_offset, end_offset, len(packets), elapsed,
    )
    return packets


def read_pcap_parallel(
    filepath: str,
    max_packets: int = 2_000_000,
    use_parallel: bool = True,
    ts_start: Optional[float] = None,
    ts_end: Optional[float] = None,
) -> List[PacketRecord]:
    """
    Read a pcap or pcapng file using dpkt, with multiprocessing for large pcap files.

    pcap files: pre-scan → split → N worker processes → merge + sort.
    pcapng files: single-threaded read_pcap_dpkt (pcapng-battle-test roadmap item).
    Falls back to single-threaded if pre-scan fails or packet count is small.

    Args:
        filepath:     Path to pcap/pcapng file
        max_packets:  Maximum packets to return
        use_parallel: Set False to disable multiprocessing (debugging/fallback)
        ts_start:     If set, skip packets with timestamp < ts_start (in workers)
        ts_end:       If set, skip packets with timestamp > ts_end (in workers)
    """
    if not use_parallel:
        logger.info("Parallel reader: disabled by use_parallel=False, using single-threaded")
        return read_pcap_dpkt(filepath, max_packets=max_packets)

    scan = _prescan_pcap(filepath)
    if scan is None:
        logger.info("Parallel reader: falling back to single-threaded (pcapng or scan failed)")
        return read_pcap_dpkt(filepath, max_packets=max_packets)

    link_type, little_endian, offsets = scan
    n_packets = len(offsets)

    try:
        n_workers = min(multiprocessing.cpu_count(), _MAX_WORKERS)
    except Exception:
        n_workers = 1

    if n_packets < _MIN_PACKETS_FOR_PARALLEL or n_workers <= 1:
        logger.info("Parallel reader: %d packets, using single-threaded", n_packets)
        return read_pcap_dpkt(filepath, max_packets=max_packets)

    logger.info("Parallel reader: %d packets across %d workers", n_packets, n_workers)

    chunk_size = max(1, n_packets // n_workers)
    chunks: List[List[int]] = [
        offsets[i: i + chunk_size] for i in range(0, n_packets, chunk_size)
    ]

    file_size = os.path.getsize(filepath)
    per_worker_cap = max(1, max_packets // n_workers)

    worker_args = []
    for i, chunk in enumerate(chunks):
        if not chunk:
            continue
        start = chunk[0]
        end = chunks[i + 1][0] if (i + 1 < len(chunks) and chunks[i + 1]) else file_size
        worker_args.append((filepath, start, end, link_type, little_endian, per_worker_cap, ts_start, ts_end))

    ctx = multiprocessing.get_context("spawn")
    try:
        with ctx.Pool(len(worker_args)) as pool:
            results: List[List[PacketRecord]] = pool.map(_worker_parse_chunk, worker_args)
    except Exception as e:
        logger.warning("Parallel read failed (%s), falling back to single-threaded", e)
        return read_pcap_dpkt(filepath, max_packets=max_packets)

    all_packets: List[PacketRecord] = []
    for chunk_result in results:
        all_packets.extend(chunk_result)
    all_packets.sort(key=lambda p: p.timestamp)
    return all_packets[:max_packets]
