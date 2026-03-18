"""
FTP dissector — extracts commands, responses, and credential indicators.

FTP is cleartext. Commands flow client→server, responses flow server→client.
The dissector handles both directions and extracts:

Commands (client→server):
  USER <username>    — login username (credential indicator)
  PASS <password>    — login password (credential — value redacted to "***")
  RETR <filename>    — file download
  STOR <filename>    — file upload
  LIST / NLST        — directory listing
  CWD <dir>          — change directory
  MKD / RMD          — make/remove directory
  DELE <file>        — delete file
  PORT / PASV / EPSV — data channel negotiation
  QUIT               — session end

Responses (server→client):
  220 service ready      — banner (may contain server software name)
  230 user logged in
  331 password required
  530 login incorrect
  550 file not found / permission denied
  425/426/227/229        — data transfer negotiation

Fields extracted:
  ftp_command        — last command verb seen
  ftp_arg            — last command argument (PASS value replaced with "***")
  ftp_response_code  — response code (int)
  ftp_response_msg   — response message text
  ftp_username       — username from USER command (not redacted — it's not a secret)
  ftp_has_credentials — True if USER+PASS sequence seen
  ftp_server_banner  — software name from 220 banner
  ftp_transfer_file  — filename from RETR/STOR
"""

from typing import Dict, Any
from . import register_dissector


_FTP_COMMANDS = {
    b"USER", b"PASS", b"ACCT", b"CWD", b"CDUP", b"SMNT",
    b"QUIT", b"REIN", b"PORT", b"PASV", b"TYPE", b"STRU",
    b"MODE", b"RETR", b"STOR", b"STOU", b"APPE", b"ALLO",
    b"REST", b"RNFR", b"RNTO", b"ABOR", b"DELE", b"RMD",
    b"MKD", b"PWD", b"LIST", b"NLST", b"SITE", b"SYST",
    b"STAT", b"HELP", b"NOOP", b"FEAT", b"OPTS", b"AUTH",
    b"PBSZ", b"PROT", b"MLST", b"MLSD", b"EPSV", b"EPRT",
}

@register_dissector("FTP")
def dissect_ftp(pkt) -> Dict[str, Any]:
    if pkt.haslayer("Raw"):
        return _extract(bytes(pkt["Raw"].load))
    return {}


def _extract(payload: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        lines = payload.split(b"\r\n")
        if not lines:
            lines = payload.split(b"\n")

        for line in lines[:5]:  # check first 5 lines
            line = line.strip()
            if not line:
                continue

            # Server response: starts with 3-digit code
            if len(line) >= 3 and line[:3].isdigit():
                code = int(line[:3])
                msg = line[4:].decode(errors="replace").strip() if len(line) > 3 else ""
                info["ftp_response_code"] = code
                info["ftp_response_msg"] = msg[:200]

                # Extract server software from 220 banner
                if code == 220 and msg:
                    info["ftp_server_banner"] = msg[:100]
                break

            # Client command: starts with a known FTP verb
            upper = line.upper()
            space_pos = line.find(b" ")
            verb = upper[:space_pos] if space_pos > 0 else upper
            arg_raw = line[space_pos + 1:] if space_pos > 0 else b""

            if verb in _FTP_COMMANDS:
                info["ftp_command"] = verb.decode()

                if verb == b"PASS":
                    info["ftp_arg"] = "***"
                    info["ftp_has_credentials"] = True
                elif verb == b"USER":
                    username = arg_raw.decode(errors="replace").strip()
                    info["ftp_arg"] = username
                    info["ftp_username"] = username
                elif verb in (b"RETR", b"STOR", b"DELE", b"RNFR", b"RNTO"):
                    filename = arg_raw.decode(errors="replace").strip()
                    info["ftp_arg"] = filename
                    info["ftp_transfer_file"] = filename
                elif verb in (b"PORT", b"EPRT"):
                    info["ftp_transfer_mode"] = "active"
                    if arg_raw:
                        info["ftp_arg"] = arg_raw.decode(errors="replace").strip()[:200]
                elif verb in (b"PASV", b"EPSV"):
                    info["ftp_transfer_mode"] = "passive"
                elif arg_raw:
                    info["ftp_arg"] = arg_raw.decode(errors="replace").strip()[:200]
                break

    except Exception:
        pass
    return info
