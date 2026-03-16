"""
Session / flow reconstruction for SwiftEye.

Groups packets into bidirectional conversations and computes
per-session metrics: TCP state, directional TTLs, directional ports,
TLS negotiation details, window sizes, etc.

This is core viewer layer — it structures raw packet data by session.
The fields computed here are direct reads from packet fields grouped
by direction, not interpretive analysis.
"""

import logging
from typing import List, Dict, Any
from collections import defaultdict

from parser.packet import PacketRecord
from parser.ja3_db import lookup_ja3

logger = logging.getLogger("swifteye.sessions")


def build_sessions(packets: List[PacketRecord]) -> List[Dict[str, Any]]:
    """
    Group packets into sessions (bidirectional flows).
    
    A session is identified by: sorted(src_ip, dst_ip) + sorted(src_port, dst_port) + transport
    
    Returns list of session dicts with aggregated metrics.
    """
    session_map: Dict[str, Dict[str, Any]] = {}
    
    for pkt in packets:
        if not pkt.src_ip or not pkt.dst_ip:
            continue
        
        key = pkt.session_key
        
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
                # TLS per-session (from packet extras)
                "tls_snis": set(),
                "tls_versions": set(),
                "tls_ciphers": set(),
                "tls_selected_ciphers": set(),
                "tls_cert": None,         # first certificate seen in this session
                # HTTP per-session
                "http_hosts": set(),
                # DNS extra
                "dns_queries": [],
                # JA3/JA4 fingerprints
                "ja3_hashes": set(),
                "ja4_hashes": set(),
                "ja3_apps": [],  # [{hash, name, category, is_malware}]
                # SSH
                "ssh_versions": set(),
                # FTP
                "ftp_commands": [],
                "ftp_usernames": set(),
                "ftp_transfer_files": [],
                "ftp_has_credentials": False,
                # DHCP
                "dhcp_hostnames": set(),
                "dhcp_vendor_classes": set(),
                "dhcp_msg_types": set(),
                # SMB
                "smb_versions": set(),
                "smb_commands": [],
                "smb_tree_paths": set(),
                "smb_filenames": set(),
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

        # IP header aggregation
        if s["ip_version"] == 0 and pkt.ip_version > 0:
            s["ip_version"] = pkt.ip_version
        # Per-direction prefix: fwd = initiator->responder, rev = the other way
        d = "fwd" if is_from_initiator else "rev"
        s[f"{d}_dscp_values"].add(pkt.dscp)
        s[f"{d}_ecn_values"].add(pkt.ecn)
        if pkt.ip_flags & 2:
            s[f"{d}_df_set"] = True
        if pkt.ip_flags & 1:
            s[f"{d}_mf_set"] = True
        if pkt.frag_offset > 0:
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
            if opt.get("kind") in ("MSS", "WScale") and len(s["tcp_options_detail"]) < 20:
                s["tcp_options_detail"].append(opt)
        
        # TLS details per session (from dissector extras)
        ex = pkt.extra
        if ex:
            if ex.get("tls_sni"):
                s["tls_snis"].add(ex["tls_sni"])
            if ex.get("tls_hello_version"):
                s["tls_versions"].add(ex["tls_hello_version"])
            if ex.get("tls_selected_cipher"):
                s["tls_selected_ciphers"].add(ex["tls_selected_cipher"])
            if ex.get("tls_cipher_suites"):
                for cs in ex["tls_cipher_suites"][:10]:
                    s["tls_ciphers"].add(cs)
            if ex.get("tls_cert") and s["tls_cert"] is None:
                s["tls_cert"] = ex["tls_cert"]  # keep first cert seen (server's leaf cert)
            if ex.get("http_host"):
                s["http_hosts"].add(ex["http_host"])
            if ex.get("ja3"):
                s["ja3_hashes"].add(ex["ja3"])
            if ex.get("ja4"):
                s["ja4_hashes"].add(ex["ja4"])
            # SSH
            if ex.get("ssh_software"):
                s["ssh_versions"].add(ex["ssh_software"])
            # FTP
            if ex.get("ftp_command"):
                s["ftp_commands"].append(ex["ftp_command"])
            if ex.get("ftp_username"):
                s["ftp_usernames"].add(ex["ftp_username"])
            if ex.get("ftp_transfer_file"):
                s["ftp_transfer_files"].append(ex["ftp_transfer_file"])
            if ex.get("ftp_has_credentials"):
                s["ftp_has_credentials"] = True
            # DHCP
            if ex.get("dhcp_hostname"):
                s["dhcp_hostnames"].add(ex["dhcp_hostname"])
            if ex.get("dhcp_vendor_class"):
                s["dhcp_vendor_classes"].add(ex["dhcp_vendor_class"])
            if ex.get("dhcp_msg_type"):
                s["dhcp_msg_types"].add(ex["dhcp_msg_type"])
            # SMB
            if ex.get("smb_version"):
                s["smb_versions"].add(ex["smb_version"])
            if ex.get("smb_command"):
                cmds = s["smb_commands"]
                if not cmds or cmds[-1] != ex["smb_command"]:  # deduplicate consecutive
                    cmds.append(ex["smb_command"])
                    if len(cmds) > 20:
                        cmds.pop(0)
            if ex.get("smb_tree_path"):
                s["smb_tree_paths"].add(ex["smb_tree_path"])
            if ex.get("smb_filename"):
                s["smb_filenames"].add(ex["smb_filename"])
        
        # DNS queries
        if pkt.extra.get("dns_query") and len(s["dns_queries"]) < 50:
            s["dns_queries"].append({
                "query": pkt.extra["dns_query"],
                "type": pkt.extra.get("dns_qtype", 0),
                "qr": pkt.extra.get("dns_qr", "query"),
                "answers": pkt.extra.get("dns_answers", []),
            })
    
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
        s["tls_snis"] = sorted(s["tls_snis"])
        s["tls_versions"] = sorted(s["tls_versions"])
        s["tls_ciphers"] = sorted(s["tls_ciphers"])[:15]
        s["tls_selected_ciphers"] = sorted(s["tls_selected_ciphers"])
        s["http_hosts"] = sorted(s["http_hosts"])
        s["ja3_hashes"] = sorted(s["ja3_hashes"])
        s["ja4_hashes"] = sorted(s["ja4_hashes"])
        ja3_apps = []
        for h in s["ja3_hashes"]:
            info = lookup_ja3(h)
            if info:
                ja3_apps.append({"hash": h, **info})
        s["ja3_apps"] = ja3_apps
        s["ssh_versions"]      = sorted(s["ssh_versions"])
        s["ftp_commands"]      = s["ftp_commands"][:20]
        s["ftp_usernames"]     = sorted(s["ftp_usernames"])
        s["ftp_transfer_files"]= list(dict.fromkeys(s["ftp_transfer_files"]))[:20]
        s["dhcp_hostnames"]    = sorted(s["dhcp_hostnames"])
        s["dhcp_vendor_classes"]= sorted(s["dhcp_vendor_classes"])
        s["dhcp_msg_types"]    = sorted(s["dhcp_msg_types"])
        s["smb_versions"]      = sorted(s["smb_versions"])
        s["smb_tree_paths"]    = sorted(s["smb_tree_paths"])
        s["smb_filenames"]     = sorted(s["smb_filenames"])[:20]
        
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
