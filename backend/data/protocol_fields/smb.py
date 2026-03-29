"""
SMB session field accumulation.

Extracts SMB fields from pkt.extra and aggregates them at the session level.
Direction-aware: operations come from the initiator, status codes from the responder.
Zeek smb_files.log and smb_mapping.log provide additional fields (service,
share_type, native_fs, file_size).

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — True if packet is from the session initiator
    source_type — "zeek" when from Zeek adapter
"""

from . import cap_list


def init():
    """Return initial session fields for SMB."""
    return {
        "smb_versions": set(),
        "smb_fwd_operations": set(),        # initiator operations
        "smb_rev_status_codes": [],         # responder NT status
        "smb_tree_paths": set(),
        "smb_filenames": set(),
        "smb_services": set(),              # Zeek: IPC, DISK, PRINTER
        "smb_share_types": set(),           # Zeek: DISK, PIPE, PRINT
    }


def accumulate(s, ex, is_fwd, source_type):
    """Accumulate SMB fields from one packet's extra dict."""
    if ex.get("smb_version"):
        s["smb_versions"].add(ex["smb_version"])
    if ex.get("smb_command"):
        # Zeek adapters set smb_command without direction context — treat as initiator
        if is_fwd or source_type == "zeek":
            s["smb_fwd_operations"].add(ex["smb_command"])
    if not is_fwd and ex.get("smb_status_name"):
        s["smb_rev_status_codes"].append(
            {"code": ex.get("smb_status", 0), "name": ex["smb_status_name"]}
        )
    if ex.get("smb_tree_path"):
        s["smb_tree_paths"].add(ex["smb_tree_path"])
    if ex.get("smb_filename"):
        s["smb_filenames"].add(ex["smb_filename"])
    if ex.get("smb_service"):
        s["smb_services"].add(ex["smb_service"])
    if ex.get("smb_share_type"):
        s["smb_share_types"].add(ex["smb_share_type"])


def serialize(s):
    """Convert SMB working fields to JSON-safe output."""
    s["smb_versions"] = sorted(s["smb_versions"])
    s["smb_fwd_operations"] = sorted(s["smb_fwd_operations"])
    cap_list(s, "smb_rev_status_codes")
    s["smb_tree_paths"] = sorted(s["smb_tree_paths"])
    s["smb_filenames"] = sorted(s["smb_filenames"])
    cap_list(s, "smb_filenames")
    s["smb_services"] = sorted(s["smb_services"])
    s["smb_share_types"] = sorted(s["smb_share_types"])
