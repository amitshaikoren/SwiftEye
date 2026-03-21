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
                # HTTP per-session — split by direction
                "http_hosts": set(),
                "http_fwd_user_agents": set(),   # initiator →
                "http_fwd_methods": set(),
                "http_fwd_uris": [],
                "http_fwd_referers": set(),
                "http_fwd_has_cookies": False,
                "http_fwd_has_auth": False,
                "http_rev_servers": set(),        # responder ←
                "http_rev_status_codes": [],
                "http_rev_content_types": set(),
                "http_rev_redirects": set(),
                "http_rev_has_set_cookies": False,
                # DNS extra
                "dns_queries": [],
                "dns_qclass_names": set(),
                # JA3/JA4 fingerprints
                "ja3_hashes": set(),
                "ja4_hashes": set(),
                "ja3_apps": [],  # [{hash, name, category, is_malware}]
                # TLS per-session — existing + new directional
                "tls_snis": set(),
                "tls_versions": set(),
                "tls_ciphers": set(),
                "tls_selected_ciphers": set(),
                "tls_cert": None,
                "tls_fwd_alpn_offered": set(),      # initiator ClientHello
                "tls_fwd_supported_versions": set(),
                "tls_fwd_extensions": set(),
                "tls_fwd_compression_methods": set(),
                "tls_rev_alpn_selected": None,       # responder ServerHello
                "tls_rev_selected_version": None,
                "tls_rev_key_exchange_group": None,
                "tls_rev_session_resumption": None,
                "tls_cert_chain": [],
                # SSH — split by direction
                "ssh_fwd_banners": set(),           # initiator
                "ssh_rev_banners": set(),           # responder
                "ssh_kex_algorithms": set(),
                "ssh_host_key_algorithms": set(),
                "ssh_encryption_c2s": set(),
                "ssh_encryption_s2c": set(),
                "ssh_mac_c2s": set(),
                "ssh_mac_s2c": set(),
                # FTP — split by direction
                "ftp_fwd_commands": [],             # initiator commands
                "ftp_fwd_transfer_mode": None,
                "ftp_rev_response_codes": [],       # responder response codes
                "ftp_rev_server_banner": None,
                "ftp_usernames": set(),
                "ftp_transfer_files": [],
                "ftp_has_credentials": False,
                # DHCP
                "dhcp_hostnames": set(),
                "dhcp_vendor_classes": set(),
                "dhcp_msg_types": set(),
                "dhcp_lease_time": None,
                "dhcp_server_ids": set(),
                "dhcp_dns_servers": set(),
                "dhcp_routers": set(),
                "dhcp_options_seen": set(),
                # SMB — split by direction
                "smb_versions": set(),
                "smb_fwd_operations": set(),        # initiator operations
                "smb_rev_status_codes": [],         # responder NT status
                "smb_tree_paths": set(),
                "smb_filenames": set(),
                # ICMP — split by direction
                "icmp_fwd_types": [],               # initiator type/code entries
                "icmp_rev_types": [],               # responder type/code entries
                "icmp_fwd_identifiers": set(),
                "icmp_rev_identifiers": set(),
                "icmp_fwd_payload_sizes": [],
                "icmp_rev_payload_sizes": [],
                "icmp_fwd_payload_samples": [],     # hex of unique payloads
                "icmp_rev_payload_samples": [],
                # Kerberos
                "krb_msg_types": set(),
                "krb_realms": set(),
                "krb_cnames": set(),
                "krb_snames": set(),
                "krb_etypes": set(),
                "krb_error_codes": [],
                # LDAP
                "ldap_ops": set(),
                "ldap_bind_dns": set(),
                "ldap_bind_mechanisms": set(),
                "ldap_search_bases": set(),
                "ldap_result_codes": [],
                "ldap_entry_dns": set(),
                # SMTP
                "smtp_ehlo_domains": set(),
                "smtp_mail_from": set(),
                "smtp_rcpt_to": set(),
                "smtp_banner": None,
                "smtp_auth_mechanisms": set(),
                "smtp_has_auth": False,
                "smtp_has_starttls": False,
                "smtp_response_codes": set(),
                # mDNS
                "mdns_queries": set(),
                "mdns_service_types": set(),
                "mdns_service_names": set(),
                "mdns_hostnames": set(),
                "mdns_txt_records": [],
                # SSDP
                "ssdp_methods": set(),
                "ssdp_sts": set(),
                "ssdp_usns": set(),
                "ssdp_locations": set(),
                "ssdp_servers": set(),
                # LLMNR
                "llmnr_queries": set(),
                "llmnr_answers": [],
                # DCE/RPC
                "dcerpc_packet_types": set(),
                "dcerpc_interfaces": [],         # [{uuid, name}] unique
                "dcerpc_opnums": set(),
                # Zeek metadata (populated only for Zeek sources)
                "zeek_uid": None,
                "zeek_conn_state": None,
                "zeek_history": None,
                "zeek_duration": None,
                "source_type": None,
                # QUIC
                "quic_versions": set(),
                "quic_dcids": set(),
                "quic_scids": set(),
                "quic_snis": set(),
                "quic_alpn": set(),
                "quic_packet_types": set(),
                "quic_tls_versions": set(),
                "quic_tls_ciphers": set(),
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
            if opt.get("kind") in ("MSS", "WScale") and len(s["tcp_options_detail"]) < 20:
                s["tcp_options_detail"].append(opt)
        
        # TLS details per session (from dissector extras)
        ex = pkt.extra
        if ex:
            # ── TLS ──
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
                s["tls_cert"] = ex["tls_cert"]
            if ex.get("tls_cert_chain"):
                if not s["tls_cert_chain"]:
                    s["tls_cert_chain"] = ex["tls_cert_chain"]
            # TLS directional (ClientHello = initiator, ServerHello = responder)
            if ex.get("tls_alpn_offered"):
                for p in ex["tls_alpn_offered"]:
                    s["tls_fwd_alpn_offered"].add(p)
            if ex.get("tls_supported_versions"):
                for v in ex["tls_supported_versions"]:
                    s["tls_fwd_supported_versions"].add(v)
            if ex.get("tls_extensions"):
                for e_id in ex["tls_extensions"]:
                    s["tls_fwd_extensions"].add(e_id)
            if ex.get("tls_compression_methods"):
                for cm in ex["tls_compression_methods"]:
                    s["tls_fwd_compression_methods"].add(cm)
            if ex.get("tls_alpn_selected") and s["tls_rev_alpn_selected"] is None:
                s["tls_rev_alpn_selected"] = ex["tls_alpn_selected"]
            if ex.get("tls_selected_version") and s["tls_rev_selected_version"] is None:
                s["tls_rev_selected_version"] = ex["tls_selected_version"]
            if ex.get("tls_key_exchange_group") and s["tls_rev_key_exchange_group"] is None:
                s["tls_rev_key_exchange_group"] = ex["tls_key_exchange_group"]
            if ex.get("tls_session_resumption") and s["tls_rev_session_resumption"] is None:
                s["tls_rev_session_resumption"] = ex["tls_session_resumption"]

            # ── HTTP — split by direction ──
            # Zeek http.log rows contain both request and response fields in a
            # single record, so we always add both sides when source_type=zeek.
            _zeek_src = ex.get("source_type") == "zeek"
            if ex.get("http_host"):
                s["http_hosts"].add(ex["http_host"])
            if is_from_initiator or _zeek_src:
                if ex.get("http_user_agent"):
                    s["http_fwd_user_agents"].add(ex["http_user_agent"])
                if ex.get("http_method"):
                    s["http_fwd_methods"].add(ex["http_method"])
                if ex.get("http_uri") and len(s["http_fwd_uris"]) < 30:
                    s["http_fwd_uris"].append(ex["http_uri"])
                if ex.get("http_referer"):
                    s["http_fwd_referers"].add(ex["http_referer"])
                if ex.get("http_cookie"):
                    s["http_fwd_has_cookies"] = True
                if ex.get("http_authorization"):
                    s["http_fwd_has_auth"] = True
            if not is_from_initiator or _zeek_src:
                if ex.get("http_server"):
                    s["http_rev_servers"].add(ex["http_server"])
                if ex.get("http_status") and len(s["http_rev_status_codes"]) < 50:
                    s["http_rev_status_codes"].append(ex["http_status"])
                if ex.get("http_content_type"):
                    s["http_rev_content_types"].add(ex["http_content_type"])
                if ex.get("http_location"):
                    s["http_rev_redirects"].add(ex["http_location"])
                if ex.get("http_set_cookie"):
                    s["http_rev_has_set_cookies"] = True

            # ── JA3/JA4 ──
            if ex.get("ja3"):
                s["ja3_hashes"].add(ex["ja3"])
            if ex.get("ja4"):
                s["ja4_hashes"].add(ex["ja4"])

            # ── SSH — split by direction ──
            if ex.get("ssh_banner"):
                if is_from_initiator:
                    s["ssh_fwd_banners"].add(ex["ssh_banner"])
                else:
                    s["ssh_rev_banners"].add(ex["ssh_banner"])
            if ex.get("ssh_kex_algorithms"):
                for a in ex["ssh_kex_algorithms"]:
                    s["ssh_kex_algorithms"].add(a)
            if ex.get("ssh_host_key_algorithms"):
                for a in ex["ssh_host_key_algorithms"]:
                    s["ssh_host_key_algorithms"].add(a)
            if ex.get("ssh_encryption_client_to_server"):
                for a in ex["ssh_encryption_client_to_server"]:
                    s["ssh_encryption_c2s"].add(a)
            if ex.get("ssh_encryption_server_to_client"):
                for a in ex["ssh_encryption_server_to_client"]:
                    s["ssh_encryption_s2c"].add(a)
            if ex.get("ssh_mac_client_to_server"):
                for a in ex["ssh_mac_client_to_server"]:
                    s["ssh_mac_c2s"].add(a)
            if ex.get("ssh_mac_server_to_client"):
                for a in ex["ssh_mac_server_to_client"]:
                    s["ssh_mac_s2c"].add(a)

            # ── FTP — split by direction ──
            if is_from_initiator:
                if ex.get("ftp_command") and len(s["ftp_fwd_commands"]) < 50:
                    s["ftp_fwd_commands"].append(ex["ftp_command"])
                if ex.get("ftp_transfer_mode") and s["ftp_fwd_transfer_mode"] is None:
                    s["ftp_fwd_transfer_mode"] = ex["ftp_transfer_mode"]
            else:
                if ex.get("ftp_response_code") and len(s["ftp_rev_response_codes"]) < 50:
                    s["ftp_rev_response_codes"].append(ex["ftp_response_code"])
                if ex.get("ftp_server_banner") and s["ftp_rev_server_banner"] is None:
                    s["ftp_rev_server_banner"] = ex["ftp_server_banner"]
            if ex.get("ftp_username"):
                s["ftp_usernames"].add(ex["ftp_username"])
            if ex.get("ftp_transfer_file"):
                s["ftp_transfer_files"].append(ex["ftp_transfer_file"])
            if ex.get("ftp_has_credentials"):
                s["ftp_has_credentials"] = True

            # ── DHCP ──
            if ex.get("dhcp_hostname"):
                s["dhcp_hostnames"].add(ex["dhcp_hostname"])
            if ex.get("dhcp_vendor_class"):
                s["dhcp_vendor_classes"].add(ex["dhcp_vendor_class"])
            if ex.get("dhcp_msg_type"):
                s["dhcp_msg_types"].add(ex["dhcp_msg_type"])
            if ex.get("dhcp_lease_time") and s["dhcp_lease_time"] is None:
                s["dhcp_lease_time"] = ex["dhcp_lease_time"]
            if ex.get("dhcp_server_id"):
                s["dhcp_server_ids"].add(ex["dhcp_server_id"])
            if ex.get("dhcp_dns_servers"):
                for dns in ex["dhcp_dns_servers"]:
                    s["dhcp_dns_servers"].add(dns)
            if ex.get("dhcp_router"):
                s["dhcp_routers"].add(ex["dhcp_router"])
            if ex.get("dhcp_options_seen"):
                for opt in ex["dhcp_options_seen"]:
                    s["dhcp_options_seen"].add(opt)

            # ── SMB — split by direction ──
            if ex.get("smb_version"):
                s["smb_versions"].add(ex["smb_version"])
            if is_from_initiator and ex.get("smb_command"):
                s["smb_fwd_operations"].add(ex["smb_command"])
            if not is_from_initiator and ex.get("smb_status_name"):
                if len(s["smb_rev_status_codes"]) < 30:
                    s["smb_rev_status_codes"].append({"code": ex.get("smb_status", 0), "name": ex["smb_status_name"]})
            if ex.get("smb_tree_path"):
                s["smb_tree_paths"].add(ex["smb_tree_path"])
            if ex.get("smb_filename"):
                s["smb_filenames"].add(ex["smb_filename"])

            # ── ICMP — split by direction ──
            if ex.get("icmp_type") is not None:
                d_prefix = "fwd" if is_from_initiator else "rev"
                type_entry = f"{ex.get('icmp_type_name', '')}:{ex.get('icmp_code_name', ex.get('icmp_code', ''))}"
                s[f"icmp_{d_prefix}_types"].append(type_entry)
                if ex.get("icmp_id") is not None:
                    s[f"icmp_{d_prefix}_identifiers"].add(ex["icmp_id"])
                if ex.get("icmp_payload_size") is not None:
                    s[f"icmp_{d_prefix}_payload_sizes"].append(ex["icmp_payload_size"])
                if ex.get("icmp_payload_hex") and len(s[f"icmp_{d_prefix}_payload_samples"]) < 10:
                    hex_val = ex["icmp_payload_hex"]
                    if hex_val not in s[f"icmp_{d_prefix}_payload_samples"]:
                        s[f"icmp_{d_prefix}_payload_samples"].append(hex_val)

            # ── Kerberos ──
            if ex.get("krb_msg_type"):
                s["krb_msg_types"].add(ex["krb_msg_type"])
            if ex.get("krb_realm"):
                s["krb_realms"].add(ex["krb_realm"])
            if ex.get("krb_cname"):
                s["krb_cnames"].add(ex["krb_cname"])
            if ex.get("krb_sname"):
                s["krb_snames"].add(ex["krb_sname"])
            if ex.get("krb_etypes"):
                for e in ex["krb_etypes"]:
                    s["krb_etypes"].add(e)
            if ex.get("krb_error_code") is not None and len(s["krb_error_codes"]) < 20:
                s["krb_error_codes"].append({"code": ex["krb_error_code"], "name": ex.get("krb_error_name", "")})

            # ── LDAP ──
            if ex.get("ldap_op"):
                s["ldap_ops"].add(ex["ldap_op"])
            if ex.get("ldap_bind_dn"):
                s["ldap_bind_dns"].add(ex["ldap_bind_dn"])
            if ex.get("ldap_bind_mechanism"):
                s["ldap_bind_mechanisms"].add(ex["ldap_bind_mechanism"])
            if ex.get("ldap_search_base"):
                s["ldap_search_bases"].add(ex["ldap_search_base"])
            if ex.get("ldap_result_code") is not None and len(s["ldap_result_codes"]) < 20:
                s["ldap_result_codes"].append({"code": ex["ldap_result_code"], "name": ex.get("ldap_result_name", "")})
            if ex.get("ldap_entry_dn"):
                s["ldap_entry_dns"].add(ex["ldap_entry_dn"])

            # ── SMTP ──
            if ex.get("smtp_ehlo_domain"):
                s["smtp_ehlo_domains"].add(ex["smtp_ehlo_domain"])
            if ex.get("smtp_mail_from"):
                s["smtp_mail_from"].add(ex["smtp_mail_from"])
            if ex.get("smtp_rcpt_to"):
                s["smtp_rcpt_to"].add(ex["smtp_rcpt_to"])
            if ex.get("smtp_banner") and s["smtp_banner"] is None:
                s["smtp_banner"] = ex["smtp_banner"]
            if ex.get("smtp_auth_mechanism"):
                s["smtp_auth_mechanisms"].add(ex["smtp_auth_mechanism"])
            if ex.get("smtp_has_auth"):
                s["smtp_has_auth"] = True
            if ex.get("smtp_has_starttls"):
                s["smtp_has_starttls"] = True
            if ex.get("smtp_response_code"):
                s["smtp_response_codes"].add(ex["smtp_response_code"])

            # ── mDNS ──
            if ex.get("mdns_query"):
                s["mdns_queries"].add(ex["mdns_query"])
            if ex.get("mdns_service_type"):
                s["mdns_service_types"].add(ex["mdns_service_type"])
            if ex.get("mdns_service_name"):
                s["mdns_service_names"].add(ex["mdns_service_name"])
            if ex.get("mdns_hostname"):
                s["mdns_hostnames"].add(ex["mdns_hostname"])
            if ex.get("mdns_txt_records") and len(s["mdns_txt_records"]) < 30:
                for t in ex["mdns_txt_records"]:
                    if t not in s["mdns_txt_records"]:
                        s["mdns_txt_records"].append(t)

            # ── SSDP ──
            if ex.get("ssdp_method"):
                s["ssdp_methods"].add(ex["ssdp_method"])
            if ex.get("ssdp_st"):
                s["ssdp_sts"].add(ex["ssdp_st"])
            if ex.get("ssdp_usn"):
                s["ssdp_usns"].add(ex["ssdp_usn"])
            if ex.get("ssdp_location"):
                s["ssdp_locations"].add(ex["ssdp_location"])
            if ex.get("ssdp_server"):
                s["ssdp_servers"].add(ex["ssdp_server"])

            # ── LLMNR ──
            if ex.get("llmnr_query"):
                s["llmnr_queries"].add(ex["llmnr_query"])
            if ex.get("llmnr_answers") and len(s["llmnr_answers"]) < 20:
                for a in ex["llmnr_answers"]:
                    if a not in s["llmnr_answers"]:
                        s["llmnr_answers"].append(a)

            # ── QUIC ──
            if ex.get("quic_version_name"):
                s["quic_versions"].add(ex["quic_version_name"])
            if ex.get("quic_dcid"):
                s["quic_dcids"].add(ex["quic_dcid"])
            if ex.get("quic_scid"):
                s["quic_scids"].add(ex["quic_scid"])
            if ex.get("quic_sni"):
                s["quic_snis"].add(ex["quic_sni"])
            if ex.get("quic_alpn"):
                for p in ex["quic_alpn"]:
                    s["quic_alpn"].add(p)
            if ex.get("quic_packet_type"):
                s["quic_packet_types"].add(ex["quic_packet_type"])
            if ex.get("quic_tls_versions"):
                for v in ex["quic_tls_versions"]:
                    s["quic_tls_versions"].add(v)
            if ex.get("quic_tls_ciphers"):
                for c in ex["quic_tls_ciphers"][:10]:
                    s["quic_tls_ciphers"].add(c)

            # ── DCE/RPC ──
            if ex.get("dcerpc_packet_type"):
                s["dcerpc_packet_types"].add(ex["dcerpc_packet_type"])
            if ex.get("dcerpc_interface_uuid") and len(s["dcerpc_interfaces"]) < 20:
                uuid = ex["dcerpc_interface_uuid"]
                name = ex.get("dcerpc_interface_name", "")
                if not any(i["uuid"] == uuid for i in s["dcerpc_interfaces"]):
                    s["dcerpc_interfaces"].append({"uuid": uuid, "name": name})
            if ex.get("dcerpc_opnum") is not None:
                s["dcerpc_opnums"].add(ex["dcerpc_opnum"])
        
        # DNS queries
        if pkt.extra.get("dns_query") and len(s["dns_queries"]) < 50:
            dns_entry = {
                "query": pkt.extra["dns_query"],
                "type": pkt.extra.get("dns_qtype", 0),
                "type_name": pkt.extra.get("dns_qtype_name", ""),
                "qclass_name": pkt.extra.get("dns_qclass_name", "IN"),
                "qr": pkt.extra.get("dns_qr", "query"),
                "rcode": pkt.extra.get("dns_rcode", 0),
                "rcode_name": pkt.extra.get("dns_rcode_name", ""),
                "answers": pkt.extra.get("dns_answers", []),
                "answer_records": pkt.extra.get("dns_answer_records", []),
                "authority_records": pkt.extra.get("dns_authority_records", []),
                "additional_records": pkt.extra.get("dns_additional_records", []),
                "flags": {},
                "tx_id": pkt.extra.get("dns_id"),
            }
            # DNS flags
            for flag_key in ("dns_aa", "dns_tc", "dns_rd", "dns_ra"):
                if pkt.extra.get(flag_key):
                    dns_entry["flags"][flag_key.replace("dns_", "")] = True
            s["dns_queries"].append(dns_entry)

        # Zeek metadata
        if pkt.extra.get("source_type") == "zeek":
            s["source_type"] = "zeek"
            if pkt.extra.get("uid"):
                s["zeek_uid"] = pkt.extra["uid"]
            if pkt.extra.get("conn_state"):
                s["zeek_conn_state"] = pkt.extra["conn_state"]
            if pkt.extra.get("history"):
                s["zeek_history"] = pkt.extra["history"]
            if pkt.extra.get("duration"):
                s["zeek_duration"] = pkt.extra["duration"]

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
        # TLS new directional
        s["tls_fwd_alpn_offered"] = sorted(s["tls_fwd_alpn_offered"])
        s["tls_fwd_supported_versions"] = sorted(s["tls_fwd_supported_versions"])
        s["tls_fwd_extensions"] = sorted(s["tls_fwd_extensions"])
        s["tls_fwd_compression_methods"] = sorted(s["tls_fwd_compression_methods"])
        # tls_rev_* scalars stay as-is (str or None)
        # tls_cert_chain stays as list of dicts

        # HTTP — directional
        s["http_hosts"] = sorted(s["http_hosts"])
        s["http_fwd_user_agents"] = sorted(s["http_fwd_user_agents"])
        s["http_fwd_methods"] = sorted(s["http_fwd_methods"])
        s["http_fwd_uris"] = list(dict.fromkeys(s["http_fwd_uris"]))[:30]
        s["http_fwd_referers"] = sorted(s["http_fwd_referers"])
        s["http_rev_servers"] = sorted(s["http_rev_servers"])
        s["http_rev_status_codes"] = s["http_rev_status_codes"][:50]
        s["http_rev_content_types"] = sorted(s["http_rev_content_types"])
        s["http_rev_redirects"] = sorted(s["http_rev_redirects"])

        s["ja3_hashes"] = sorted(s["ja3_hashes"])
        s["ja4_hashes"] = sorted(s["ja4_hashes"])
        ja3_apps = []
        for h in s["ja3_hashes"]:
            info = lookup_ja3(h)
            if info:
                ja3_apps.append({"hash": h, **info})
        s["ja3_apps"] = ja3_apps

        # SSH — directional
        s["ssh_fwd_banners"] = sorted(s["ssh_fwd_banners"])
        s["ssh_rev_banners"] = sorted(s["ssh_rev_banners"])
        s["ssh_kex_algorithms"] = sorted(s["ssh_kex_algorithms"])
        s["ssh_host_key_algorithms"] = sorted(s["ssh_host_key_algorithms"])
        s["ssh_encryption_c2s"] = sorted(s["ssh_encryption_c2s"])
        s["ssh_encryption_s2c"] = sorted(s["ssh_encryption_s2c"])
        s["ssh_mac_c2s"] = sorted(s["ssh_mac_c2s"])
        s["ssh_mac_s2c"] = sorted(s["ssh_mac_s2c"])

        # FTP — directional
        s["ftp_fwd_commands"] = s["ftp_fwd_commands"][:50]
        s["ftp_rev_response_codes"] = s["ftp_rev_response_codes"][:50]
        s["ftp_usernames"] = sorted(s["ftp_usernames"])
        s["ftp_transfer_files"] = list(dict.fromkeys(s["ftp_transfer_files"]))[:20]

        # DHCP
        s["dhcp_hostnames"]    = sorted(s["dhcp_hostnames"])
        s["dhcp_vendor_classes"]= sorted(s["dhcp_vendor_classes"])
        s["dhcp_msg_types"]    = sorted(s["dhcp_msg_types"])
        s["dhcp_server_ids"]   = sorted(s["dhcp_server_ids"])
        s["dhcp_dns_servers"]  = sorted(s["dhcp_dns_servers"])
        s["dhcp_routers"]      = sorted(s["dhcp_routers"])
        s["dhcp_options_seen"] = sorted(s["dhcp_options_seen"])

        # SMB — directional
        s["smb_versions"]      = sorted(s["smb_versions"])
        s["smb_fwd_operations"]= sorted(s["smb_fwd_operations"])
        s["smb_rev_status_codes"] = s["smb_rev_status_codes"][:30]
        s["smb_tree_paths"]    = sorted(s["smb_tree_paths"])
        s["smb_filenames"]     = sorted(s["smb_filenames"])[:20]

        # ICMP — directional (aggregate type counts)
        def _icmp_type_counts(type_list):
            counts = {}
            for t in type_list:
                counts[t] = counts.get(t, 0) + 1
            return [{"type_desc": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])]
        s["icmp_fwd_types"] = _icmp_type_counts(s["icmp_fwd_types"])
        s["icmp_rev_types"] = _icmp_type_counts(s["icmp_rev_types"])
        s["icmp_fwd_identifiers"] = sorted(s["icmp_fwd_identifiers"])
        s["icmp_rev_identifiers"] = sorted(s["icmp_rev_identifiers"])

        # Kerberos
        s["krb_msg_types"] = sorted(s["krb_msg_types"])
        s["krb_realms"] = sorted(s["krb_realms"])
        s["krb_cnames"] = sorted(s["krb_cnames"])
        s["krb_snames"] = sorted(s["krb_snames"])
        s["krb_etypes"] = sorted(s["krb_etypes"])

        # LDAP
        s["ldap_ops"] = sorted(s["ldap_ops"])
        s["ldap_bind_dns"] = sorted(s["ldap_bind_dns"])
        s["ldap_bind_mechanisms"] = sorted(s["ldap_bind_mechanisms"])
        s["ldap_search_bases"] = sorted(s["ldap_search_bases"])
        s["ldap_entry_dns"] = sorted(s["ldap_entry_dns"])[:20]

        # SMTP
        s["smtp_ehlo_domains"] = sorted(s["smtp_ehlo_domains"])
        s["smtp_mail_from"] = sorted(s["smtp_mail_from"])
        s["smtp_rcpt_to"] = sorted(s["smtp_rcpt_to"])
        s["smtp_auth_mechanisms"] = sorted(s["smtp_auth_mechanisms"])
        s["smtp_response_codes"] = sorted(s["smtp_response_codes"])

        # mDNS
        s["mdns_queries"] = sorted(s["mdns_queries"])
        s["mdns_service_types"] = sorted(s["mdns_service_types"])
        s["mdns_service_names"] = sorted(s["mdns_service_names"])
        s["mdns_hostnames"] = sorted(s["mdns_hostnames"])
        s["mdns_txt_records"] = s["mdns_txt_records"][:30]

        # SSDP
        s["ssdp_methods"] = sorted(s["ssdp_methods"])
        s["ssdp_sts"] = sorted(s["ssdp_sts"])[:20]
        s["ssdp_usns"] = sorted(s["ssdp_usns"])[:20]
        s["ssdp_locations"] = sorted(s["ssdp_locations"])[:20]
        s["ssdp_servers"] = sorted(s["ssdp_servers"])

        # LLMNR
        s["llmnr_queries"] = sorted(s["llmnr_queries"])
        s["llmnr_answers"] = s["llmnr_answers"][:20]

        # DCE/RPC
        s["dcerpc_packet_types"] = sorted(s["dcerpc_packet_types"])
        s["dcerpc_interfaces"] = s["dcerpc_interfaces"][:20]
        s["dcerpc_opnums"] = sorted(s["dcerpc_opnums"])

        # QUIC
        s["quic_versions"] = sorted(s["quic_versions"])
        s["quic_dcids"] = sorted(s["quic_dcids"])[:10]
        s["quic_scids"] = sorted(s["quic_scids"])[:10]
        s["quic_snis"] = sorted(s["quic_snis"])
        s["quic_alpn"] = sorted(s["quic_alpn"])
        s["quic_packet_types"] = sorted(s["quic_packet_types"])
        s["quic_tls_versions"] = sorted(s["quic_tls_versions"])
        s["quic_tls_ciphers"] = sorted(s["quic_tls_ciphers"])[:15]

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
