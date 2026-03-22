"""
SMB session field accumulation.

Extracts SMB fields from pkt.extra and aggregates them at the session level.
Direction-aware: operations come from the initiator, status codes from the responder.

Key variables:
    s        — session dict (mutable)
    ex       — pkt.extra from current packet (read-only)
    is_fwd      — True if packet is from the session initiator
    source_type — unused for SMB (no Zeek SMB adapter yet)
"""

CAP_SMB_STATUS_CODES = 30
CAP_SMB_FILENAMES = 20


def init():
    """Return initial session fields for SMB."""
    return {
        "smb_versions": set(),
        "smb_fwd_operations": set(),        # initiator operations
        "smb_rev_status_codes": [],         # responder NT status
        "smb_tree_paths": set(),
        "smb_filenames": set(),
    }


def accumulate(s, ex, is_fwd, source_type):
    """Accumulate SMB fields from one packet's extra dict."""
    if ex.get("smb_version"):
        s["smb_versions"].add(ex["smb_version"])
    if is_fwd and ex.get("smb_command"):
        s["smb_fwd_operations"].add(ex["smb_command"])
    if not is_fwd and ex.get("smb_status_name"):
        if len(s["smb_rev_status_codes"]) < CAP_SMB_STATUS_CODES:
            s["smb_rev_status_codes"].append(
                {"code": ex.get("smb_status", 0), "name": ex["smb_status_name"]}
            )
    if ex.get("smb_tree_path"):
        s["smb_tree_paths"].add(ex["smb_tree_path"])
    if ex.get("smb_filename"):
        s["smb_filenames"].add(ex["smb_filename"])


def serialize(s):
    """Convert SMB working fields to JSON-safe output."""
    s["smb_versions"] = sorted(s["smb_versions"])
    s["smb_fwd_operations"] = sorted(s["smb_fwd_operations"])
    s["smb_rev_status_codes"] = s["smb_rev_status_codes"][:CAP_SMB_STATUS_CODES]
    s["smb_tree_paths"] = sorted(s["smb_tree_paths"])
    s["smb_filenames"] = sorted(s["smb_filenames"])[:CAP_SMB_FILENAMES]
