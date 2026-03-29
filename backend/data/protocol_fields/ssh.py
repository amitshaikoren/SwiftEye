"""
SSH session field accumulation.

Direction-aware: banners split by initiator/responder.
Algorithm lists (kex, encryption, mac) are session-wide.

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — True if packet is from the session initiator
    source_type — unused for SSH currently
"""


def init():
    return {
        "ssh_fwd_banners": set(),
        "ssh_rev_banners": set(),
        "ssh_kex_algorithms": set(),
        "ssh_host_key_algorithms": set(),
        "ssh_encryption_c2s": set(),
        "ssh_encryption_s2c": set(),
        "ssh_mac_c2s": set(),
        "ssh_mac_s2c": set(),
    }


def accumulate(s, ex, is_fwd, source_type):
    if ex.get("ssh_banner"):
        if is_fwd:
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


def serialize(s):
    s["ssh_fwd_banners"] = sorted(s["ssh_fwd_banners"])
    s["ssh_rev_banners"] = sorted(s["ssh_rev_banners"])
    s["ssh_kex_algorithms"] = sorted(s["ssh_kex_algorithms"])
    s["ssh_host_key_algorithms"] = sorted(s["ssh_host_key_algorithms"])
    s["ssh_encryption_c2s"] = sorted(s["ssh_encryption_c2s"])
    s["ssh_encryption_s2c"] = sorted(s["ssh_encryption_s2c"])
    s["ssh_mac_c2s"] = sorted(s["ssh_mac_c2s"])
    s["ssh_mac_s2c"] = sorted(s["ssh_mac_s2c"])
