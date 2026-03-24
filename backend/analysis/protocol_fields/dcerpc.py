"""
DCE/RPC session field accumulation.

Custom: interfaces are deduplicated by UUID (structured unique append).

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — unused (DCE/RPC ops are session-wide)
    source_type — unused
"""

from analysis.protocol_fields import cap_list


def init():
    return {
        "dcerpc_packet_types": set(),
        "dcerpc_interfaces": [],
        "dcerpc_opnums": set(),
    }


def accumulate(s, ex, is_fwd, source_type):
    if ex.get("dcerpc_packet_type"):
        s["dcerpc_packet_types"].add(ex["dcerpc_packet_type"])
    if ex.get("dcerpc_interface_uuid"):
        uuid = ex["dcerpc_interface_uuid"]
        name = ex.get("dcerpc_interface_name", "")
        if not any(i["uuid"] == uuid for i in s["dcerpc_interfaces"]):
            s["dcerpc_interfaces"].append({"uuid": uuid, "name": name})
    if ex.get("dcerpc_opnum") is not None:
        s["dcerpc_opnums"].add(ex["dcerpc_opnum"])


def serialize(s):
    s["dcerpc_packet_types"] = sorted(s["dcerpc_packet_types"])
    cap_list(s, "dcerpc_interfaces")
    s["dcerpc_opnums"] = sorted(s["dcerpc_opnums"])
