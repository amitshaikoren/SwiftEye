"""
FTP session field accumulation.

Direction-aware: commands from initiator, response codes/banner from responder.
Usernames and transfer files are session-wide.

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — True if packet is from the session initiator
    source_type — unused for FTP currently
"""

from . import cap_list


def init():
    return {
        "ftp_fwd_commands": [],
        "ftp_fwd_transfer_mode": None,
        "ftp_rev_response_codes": [],
        "ftp_rev_server_banner": None,
        "ftp_usernames": set(),
        "ftp_transfer_files": [],
        "ftp_has_credentials": False,
    }


def accumulate(s, ex, is_fwd, source_type):
    if is_fwd:
        if ex.get("ftp_command"):
            s["ftp_fwd_commands"].append(ex["ftp_command"])
        if ex.get("ftp_transfer_mode") and s["ftp_fwd_transfer_mode"] is None:
            s["ftp_fwd_transfer_mode"] = ex["ftp_transfer_mode"]
    else:
        if ex.get("ftp_response_code"):
            s["ftp_rev_response_codes"].append(ex["ftp_response_code"])
        if ex.get("ftp_server_banner") and s["ftp_rev_server_banner"] is None:
            s["ftp_rev_server_banner"] = ex["ftp_server_banner"]
    if ex.get("ftp_username"):
        s["ftp_usernames"].add(ex["ftp_username"])
    if ex.get("ftp_transfer_file"):
        s["ftp_transfer_files"].append(ex["ftp_transfer_file"])
    if ex.get("ftp_has_credentials"):
        s["ftp_has_credentials"] = True


def serialize(s):
    cap_list(s, "ftp_fwd_commands")
    cap_list(s, "ftp_rev_response_codes")
    s["ftp_usernames"] = sorted(s["ftp_usernames"])
    s["ftp_transfer_files"] = list(dict.fromkeys(s["ftp_transfer_files"]))
    cap_list(s, "ftp_transfer_files")
