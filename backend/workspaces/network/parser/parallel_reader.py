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
import struct
import time
from typing import List, Optional, Tuple

from .packet import PacketRecord
from .dpkt_reader import _parse_raw, read_pcap_dpkt

logger = logging.getLogger("swifteye.parser.parallel")

_MAX_WORKERS = 8
_MIN_PACKETS_FOR_PARALLEL = 10_000


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


def _worker_parse_chunk(args: tuple) -> List[PacketRecord]:
    """
    Worker function. Runs in a spawned child process.
    Reads packets from start_offset to end_offset (byte positions) using
    direct struct reads — does NOT use dpkt.pcap.Reader to avoid buffering
    issues that cause the reader to ignore seeks.
    """
    filepath, start_offset, end_offset, link_type, little_endian, max_pkts = args
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
            raw = f.read(incl_len)
            if len(raw) < incl_len:
                break
            ts = ts_sec + ts_usec * 1e-6
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
) -> List[PacketRecord]:
    """
    Read a pcap or pcapng file using dpkt, with multiprocessing for large pcap files.

    pcap files: pre-scan → split → N worker processes → merge + sort.
    pcapng files: single-threaded read_pcap_dpkt (pcapng-battle-test roadmap item).
    Falls back to single-threaded if pre-scan fails or packet count is small.

    Args:
        filepath: Path to pcap/pcapng file
        max_packets: Maximum packets to return
        use_parallel: Set False to disable multiprocessing (debugging/fallback)
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
    # Cap per worker so we never sort more than max_packets objects total.
    # Each worker takes the first N packets from its time-range slice.
    per_worker_cap = max(1, max_packets // n_workers)

    worker_args = []
    for i, chunk in enumerate(chunks):
        if not chunk:
            continue
        start = chunk[0]
        # end = start of first packet in next chunk, or EOF for the last chunk
        end = chunks[i + 1][0] if (i + 1 < len(chunks) and chunks[i + 1]) else file_size
        worker_args.append((filepath, start, end, link_type, little_endian, per_worker_cap))

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
