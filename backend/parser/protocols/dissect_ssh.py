"""
SSH dissector — extracts banner version and software fingerprint.

The SSH banner is sent in cleartext on both ends immediately after the
TCP connection is established, before any encryption. Format:
  SSH-<protoversion>-<softwareversion> [comments]\r\n

Examples:
  SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
  SSH-2.0-libssh_0.10.5
  SSH-2.0-PuTTY_Release_0.80
  SSH-1.99-Cisco-1.25

Fields extracted:
  ssh_proto_version  — "2.0", "1.99", "1.5" etc.
  ssh_software       — full software string ("OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
  ssh_client         — True if this looks like a client banner (heuristic)
  ssh_banner         — full raw banner line (for reference)
"""

import struct
from typing import Dict, Any
from . import register_dissector, register_payload_signature


@register_payload_signature("SSH", priority=20)
def _detect_ssh(payload: bytes) -> bool:
    return payload[:4] == b"SSH-"


@register_dissector("SSH")
def dissect_ssh(pkt) -> Dict[str, Any]:
    if pkt.haslayer("Raw"):
        return _extract(bytes(pkt["Raw"].load))
    return {}


def _extract(payload: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        # SSH banner: "SSH-<proto>-<software>[ comments]\r\n"
        if payload.startswith(b"SSH-"):
            line = payload.split(b"\r\n")[0].split(b"\n")[0]
            banner = line.decode(errors="replace").strip()
            info["ssh_banner"] = banner

            parts = banner[4:].split("-", 1)
            if len(parts) >= 2:
                info["ssh_proto_version"] = parts[0]
                software_and_comment = parts[1]
                sw_parts = software_and_comment.split(" ", 1)
                info["ssh_software"] = software_and_comment
                info["ssh_software_name"] = sw_parts[0]

                sw_lower = sw_parts[0].lower()
                known_servers = ("openssh", "dropbear", "cisco", "libssh", "bitvise",
                                 "vandyke", "ssh.com", "tectia", "paramiko")
                known_clients = ("putty", "filezilla", "winscp", "securecrt",
                                 "mobaxterm", "xshell", "nmap")
                if any(k in sw_lower for k in known_clients):
                    info["ssh_client"] = True
                elif any(k in sw_lower for k in known_servers):
                    info["ssh_client"] = False
            elif len(parts) == 1:
                info["ssh_proto_version"] = parts[0]

            # Check if KEX_INIT follows banner in the same packet
            rest = payload[len(line) + 2:]  # skip banner + \r\n
            if rest and len(rest) >= 5:
                kex = _parse_kex_init(rest)
                if kex:
                    info.update(kex)

        # SSH binary packet (no banner) — could be KEX_INIT
        elif len(payload) >= 5:
            kex = _parse_kex_init(payload)
            if kex:
                info.update(kex)

    except Exception:
        pass
    return info


def _parse_kex_init(data: bytes) -> Dict[str, Any]:
    """Parse an SSH KEX_INIT message (msg type 20) from raw binary packet data.
    SSH binary packet format: uint32 packet_length, byte padding_length, byte msg_type, ...
    KEX_INIT (type 20) payload after 16-byte cookie: 10 name-lists (comma-separated strings).
    """
    info: Dict[str, Any] = {}
    try:
        if len(data) < 6:
            return info
        pkt_len = struct.unpack_from("!I", data, 0)[0]
        if pkt_len < 2 or pkt_len > 65535:
            return info
        pad_len = data[4]
        msg_type = data[5]
        if msg_type != 20:  # SSH_MSG_KEXINIT
            return info

        # Skip: 4 (pkt_len) + 1 (pad_len) + 1 (msg_type) + 16 (cookie) = 22
        off = 22
        if off >= len(data):
            return info

        # 10 name-lists in order per RFC 4253:
        fields = [
            "ssh_kex_algorithms",
            "ssh_host_key_algorithms",
            "ssh_encryption_client_to_server",
            "ssh_encryption_server_to_client",
            "ssh_mac_client_to_server",
            "ssh_mac_server_to_client",
            "ssh_compression_client_to_server",
            "ssh_compression_server_to_client",
            "ssh_languages_client_to_server",
            "ssh_languages_server_to_client",
        ]

        for field in fields:
            if off + 4 > len(data):
                break
            name_len = struct.unpack_from("!I", data, off)[0]
            off += 4
            if off + name_len > len(data) or name_len > 10000:
                break
            name_list = data[off:off + name_len].decode(errors="replace")
            off += name_len
            if name_list:
                info[field] = name_list.split(",")

    except Exception:
        pass
    return info
