"""
Session / flow reconstruction for SwiftEye.

Groups packets into bidirectional conversations and computes
per-session metrics: TCP state, directional TTLs, directional ports,
window sizes, etc.  Protocol-specific fields (TLS, HTTP, DNS, …) are
handled by auto-discovered modules in analysis/protocol_fields/.

Session boundary detection splits flows that reuse the same 5-tuple
(src/dst IP + ports + transport) into separate sessions using three
heuristic signals:
  1. TCP FIN/RST close followed by SYN reopen
  2. Large timestamp gap (60s UDP, 120s TCP)
  3. TCP sequence number jump + moderate time gap (catches lost FIN/RST)
False non-splits are preferred over false splits — when in doubt, keep
packets in the same session.

This is core viewer layer — it structures raw packet data by session.
The fields computed here are direct reads from packet fields grouped
by direction, not interpretive analysis.
"""

import logging
from typing import List, Dict, Any
from collections import defaultdict

from parser.packet import PacketRecord
from analysis.protocol_fields import all_accumulate, all_serialize

logger = logging.getLogger("swifteye.sessions")

# ── Session boundary detection thresholds ─────────────────────────
# Conservative values — false non-splits are better than false splits.
UDP_GAP_THRESHOLD = 60.0         # seconds before a UDP flow is considered stale
TCP_GAP_THRESHOLD = 120.0        # seconds — TCP can have long keepalives
SEQ_JUMP_THRESHOLD = 1_000_000   # seq delta that suggests a new connection (not retransmit)
SEQ_JUMP_GAP = 5.0               # seconds — seq jump alone isn't enough, needs a time gap too


def _check_boundary(flow_state: dict, pkt, is_tcp: bool) -> bool:
    """
    Decide whether *pkt* starts a new session on an existing 5-tuple.

    Returns True if a boundary is detected (caller should bump generation).
    Mutates flow_state to track close/timestamp/seq for future checks.
    """
    split = False

    # ── Signal 1: TCP FIN/RST close → SYN reopen ──
    if is_tcp and flow_state["closed"] and pkt.tcp_flags_list:
        if "SYN" in pkt.tcp_flags_list and "ACK" not in pkt.tcp_flags_list:
            split = True

    # ── Signal 2: timestamp gap ──
    last_ts = flow_state["last_ts"]
    if not split and last_ts > 0:
        gap = pkt.timestamp - last_ts
        threshold = TCP_GAP_THRESHOLD if is_tcp else UDP_GAP_THRESHOLD
        if gap > threshold:
            split = True

    # ── Signal 3: TCP seq jump + moderate time gap ──
    if not split and is_tcp and pkt.seq_num > 0:
        last_seq = flow_state["last_seq"]
        if last_seq > 0:
            delta = abs(pkt.seq_num - last_seq)
            gap = pkt.timestamp - last_ts if last_ts > 0 else 0
            if delta > SEQ_JUMP_THRESHOLD and gap > SEQ_JUMP_GAP:
                split = True

    # ── Update flow state ──
    flow_state["last_ts"] = pkt.timestamp
    if is_tcp and pkt.tcp_flags_list:
        if "FIN" in pkt.tcp_flags_list or "RST" in pkt.tcp_flags_list:
            flow_state["closed"] = True
    if is_tcp and pkt.seq_num > 0:
        flow_state["last_seq"] = pkt.seq_num

    if split:
        # Reset state for the new generation
        flow_state["closed"] = False
        flow_state["last_seq"] = 0

    return split


def build_sessions(packets: List[PacketRecord]) -> List[Dict[str, Any]]:
    """
    Group packets into sessions (bidirectional flows).

    A session is identified by: sorted(src_ip, dst_ip) + sorted(src_port, dst_port) + transport.
    Flows that reuse the same 5-tuple are split into separate sessions
    when boundary heuristics fire (FIN/RST+SYN, timestamp gap, seq jump).

    Returns list of session dicts with aggregated metrics.
    """
    session_map: Dict[str, Dict[str, Any]] = {}

    # Per-5-tuple state for boundary detection
    flow_generation: Dict[str, int] = {}
    flow_state: Dict[str, dict] = {}

    for pkt in packets:
        if not pkt.src_ip or not pkt.dst_ip:
            continue

        base_key = pkt.session_key
        is_tcp = pkt.transport == "TCP"

        # ── Boundary detection ──
        if base_key not in flow_generation:
            flow_generation[base_key] = 0
            flow_state[base_key] = {"closed": False, "last_ts": 0, "last_seq": 0}
        elif _check_boundary(flow_state[base_key], pkt, is_tcp):
            flow_generation[base_key] += 1

        gen = flow_generation[base_key]
        key = f"{base_key}#{gen}" if gen > 0 else base_key

        if key not in session_map:
            ips = sorted([pkt.src_ip, pkt.dst_ip])
            ports = sorted([pkt.src_port, pkt.dst_port])
            session_map[key] = {
                "id": key,
                "src_ip": ips[0],
                "dst_ip": ips[1],
                "src_port": ports[0],
                "dst_port": ports[1],
                "protocol": pkt.protocol,
                "transport": pkt.transport,
                "packet_count": 0,
                "total_bytes": 0,
                "payload_bytes": 0,
                "start_time": pkt.timestamp,
                "end_time": pkt.timestamp,
                # Direction tracking
                "fwd_packets": 0,
                "fwd_bytes": 0,
                "fwd_payload_bytes": 0,
                "rev_packets": 0,
                "rev_bytes": 0,
                "rev_payload_bytes": 0,
                # TCP state
                "flag_counts": defaultdict(int),
                "ttls": set(),
                "ttls_initiator": set(),
                "ttls_responder": set(),
                # IP header fields — per direction (fwd=initiator, rev=responder)
                "ip_version": 0,
                "fwd_dscp_values": set(), "rev_dscp_values": set(),
                "fwd_ecn_values":  set(), "rev_ecn_values":  set(),
                "fwd_df_set": False,      "rev_df_set": False,
                "fwd_mf_set": False,      "rev_mf_set": False,
                "fwd_frag_seen": False,   "rev_frag_seen": False,
                "fwd_ip_id_min": None,    "rev_ip_id_min": None,
                "fwd_ip_id_max": None,    "rev_ip_id_max": None,
                "ip6_flow_labels": set(), # IPv6 flow labels seen (usually one per flow)
                "window_sizes": [],
                "init_window_initiator": 0,  # first window size from initiator
                "init_window_responder": 0,  # first window size from responder
                "seq_isn_init": 0,   # initial sequence number from initiator (for relative display)
                "seq_isn_resp": 0,   # initial sequence number from responder
                "seq_nums": [],
                "ack_nums": [],
                "tcp_options_seen": set(),
                "tcp_options_detail": [],
                "has_handshake": False,
                "has_fin": False,
                "has_reset": False,
                # Initiator tracking
                "initiator_ip": "",
                "initiator_port": 0,
                "responder_ip": "",
                "responder_port": 0,
                # Directional ports
                "initiator_ports": set(),
                "responder_ports": set(),
                # Protocol fields: lazy-initialized by all_accumulate() on first
                # relevant packet. No pre-loading — see protocol_fields/__init__.py.
            }
        
        s = session_map[key]
        s["packet_count"] += 1
        s["total_bytes"] += pkt.orig_len
        s["payload_bytes"] += pkt.payload_len
        s["end_time"] = max(s["end_time"], pkt.timestamp)
        
        # For non-TCP or if no SYN seen, first packet sender is initiator
        if not s["initiator_ip"] and s["packet_count"] == 1:
            s["initiator_ip"] = pkt.src_ip
            s["initiator_port"] = pkt.src_port
            s["responder_ip"] = pkt.dst_ip
            s["responder_port"] = pkt.dst_port
        
        # TCP SYN-based initiator override (more accurate than first-packet)
        if pkt.tcp_flags_list:
            for flag in pkt.tcp_flags_list:
                s["flag_counts"][flag] += 1
            if "SYN" in pkt.tcp_flags_list and "ACK" not in pkt.tcp_flags_list:
                # Pure SYN = connection initiator — override first-packet guess
                s["initiator_ip"] = pkt.src_ip
                s["initiator_port"] = pkt.src_port
                s["responder_ip"] = pkt.dst_ip
                s["responder_port"] = pkt.dst_port
        
        # Determine if this packet is from the initiator
        is_from_initiator = (
            s["initiator_ip"] and pkt.src_ip == s["initiator_ip"]
        )
        
        # Direction tracking (forward = initiator→responder)
        if is_from_initiator:
            s["fwd_packets"] += 1
            s["fwd_bytes"] += pkt.orig_len
            s["fwd_payload_bytes"] += pkt.payload_len
        else:
            s["rev_packets"] += 1
            s["rev_bytes"] += pkt.orig_len
            s["rev_payload_bytes"] += pkt.payload_len
        
        # Directional TTLs
        if pkt.ttl > 0:
            s["ttls"].add(pkt.ttl)
            if is_from_initiator:
                s["ttls_initiator"].add(pkt.ttl)
            else:
                s["ttls_responder"].add(pkt.ttl)

        # IP header aggregation — only for sources that provide raw IP headers
        # (Zeek conn.log provides ip_version but not DSCP/ECN/flags/etc.)
        _has_ip_headers = not getattr(pkt, 'extra', {}).get("source_type")
        if s["ip_version"] == 0 and pkt.ip_version > 0:
            s["ip_version"] = pkt.ip_version
        # Per-direction prefix: fwd = initiator->responder, rev = the other way
        d = "fwd" if is_from_initiator else "rev"
        if _has_ip_headers:
            s[f"{d}_dscp_values"].add(pkt.dscp)
            s[f"{d}_ecn_values"].add(pkt.ecn)
        if _has_ip_headers and pkt.ip_flags & 2:
            s[f"{d}_df_set"] = True
        if _has_ip_headers and pkt.ip_flags & 1:
            s[f"{d}_mf_set"] = True
        if _has_ip_headers and pkt.frag_offset > 0:
            s[f"{d}_frag_seen"] = True
        if pkt.ip_version == 4 and pkt.ip_id > 0:
            k_min, k_max = f"{d}_ip_id_min", f"{d}_ip_id_max"
            s[k_min] = pkt.ip_id if s[k_min] is None else min(s[k_min], pkt.ip_id)
            s[k_max] = pkt.ip_id if s[k_max] is None else max(s[k_max], pkt.ip_id)
        if pkt.ip6_flow_label > 0:
            s["ip6_flow_labels"].add(pkt.ip6_flow_label)
        
        # Directional ports
        if pkt.src_port > 0:
            if is_from_initiator:
                s["initiator_ports"].add(pkt.src_port)
                if pkt.dst_port > 0:
                    s["responder_ports"].add(pkt.dst_port)
            else:
                s["responder_ports"].add(pkt.src_port)
                if pkt.dst_port > 0:
                    s["initiator_ports"].add(pkt.dst_port)
        
        # Window / Seq / Ack
        if pkt.window_size > 0:
            s["window_sizes"].append(pkt.window_size)
            # Track initial (first seen) window size per direction
            if is_from_initiator and s["init_window_initiator"] == 0:
                s["init_window_initiator"] = pkt.window_size
            elif not is_from_initiator and s["init_window_responder"] == 0:
                s["init_window_responder"] = pkt.window_size
        if pkt.seq_num > 0:
            s["seq_nums"].append(pkt.seq_num)
            # Track ISN per direction (first SEQ seen from each side)
            if is_from_initiator and s["seq_isn_init"] == 0:
                s["seq_isn_init"] = pkt.seq_num
            elif not is_from_initiator and s["seq_isn_resp"] == 0:
                s["seq_isn_resp"] = pkt.seq_num
        if pkt.ack_num > 0:
            s["ack_nums"].append(pkt.ack_num)
        
        # TCP options
        for opt in pkt.tcp_options:
            s["tcp_options_seen"].add(opt.get("kind", ""))
            if opt.get("kind") in ("MSS", "WScale"):
                s["tcp_options_detail"].append(opt)
        
        # ── Protocol fields (auto-discovered from protocol_fields/) ──
        ex = pkt.extra
        if ex:
            all_accumulate(s, ex, is_from_initiator, ex.get("source_type"))

    # Post-process sessions
    results = []
    for s in session_map.values():
        s["flag_counts"] = dict(s["flag_counts"])
        s["ttls"] = sorted(s["ttls"])
        s["ttls_initiator"] = sorted(s["ttls_initiator"])
        s["ttls_responder"] = sorted(s["ttls_responder"])
        # IP header fields — serialise sets to sorted lists
        for d in ("fwd", "rev"):
            s[f"{d}_dscp_values"] = sorted(s[f"{d}_dscp_values"])
            s[f"{d}_ecn_values"]  = sorted(s[f"{d}_ecn_values"])
        s["ip6_flow_labels"] = sorted(s["ip6_flow_labels"])
        # ip_id_min/max stay as int or None — JSON serialises fine
        s["tcp_options_seen"] = sorted(s["tcp_options_seen"])
        s["initiator_ports"] = sorted(s["initiator_ports"])
        s["responder_ports"] = sorted(s["responder_ports"])
        # ── Protocol fields (auto-discovered) ──
        all_serialize(s)

        # TCP state detection
        fc = s["flag_counts"]
        s["has_handshake"] = fc.get("SYN", 0) >= 2 and fc.get("ACK", 0) >= 1
        s["has_fin"] = fc.get("FIN", 0) >= 1
        s["has_reset"] = fc.get("RST", 0) >= 1
        
        # Window stats
        ws = s["window_sizes"]
        if ws:
            s["window_min"] = min(ws)
            s["window_max"] = max(ws)
            s["window_avg"] = round(sum(ws) / len(ws))
        else:
            s["window_min"] = s["window_max"] = s["window_avg"] = 0
        
        # TTL stats
        if s["ttls"]:
            s["ttl_min"] = s["ttls"][0]
            s["ttl_max"] = s["ttls"][-1]
        else:
            s["ttl_min"] = s["ttl_max"] = 0
        
        # Seq/Ack range
        if s["seq_nums"]:
            s["seq_first"] = s["seq_nums"][0]
            s["seq_last"] = s["seq_nums"][-1]
        else:
            s["seq_first"] = s["seq_last"] = 0
        
        if s["ack_nums"]:
            s["ack_first"] = s["ack_nums"][0]
            s["ack_last"] = s["ack_nums"][-1]
        else:
            s["ack_first"] = s["ack_last"] = 0
        
        s["duration"] = s["end_time"] - s["start_time"]
        
        # Remove raw lists to save memory (keep only stats)
        del s["window_sizes"]
        del s["seq_nums"]
        del s["ack_nums"]
        
        results.append(s)
    
    results.sort(key=lambda s: s["total_bytes"], reverse=True)
    return results
