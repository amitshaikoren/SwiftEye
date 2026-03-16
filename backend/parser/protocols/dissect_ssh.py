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
        if not payload.startswith(b"SSH-"):
            return info

        line = payload.split(b"\r\n")[0].split(b"\n")[0]
        banner = line.decode(errors="replace").strip()
        info["ssh_banner"] = banner

        # SSH-<proto>-<software>[ comments]
        parts = banner[4:].split("-", 1)  # strip leading "SSH-"
        if len(parts) >= 2:
            info["ssh_proto_version"] = parts[0]
            software_and_comment = parts[1]
            # Comments are separated by a space (RFC 4253)
            sw_parts = software_and_comment.split(" ", 1)
            info["ssh_software"] = software_and_comment  # full string inc. comment
            info["ssh_software_name"] = sw_parts[0]      # just the version token

            # Heuristic: server banners often include OS info or known server names.
            # Client banners are usually just the library name.
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

    except Exception:
        pass
    return info
