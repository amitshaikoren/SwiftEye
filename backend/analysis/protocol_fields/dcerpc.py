"""
DCE/RPC session field accumulation.

Custom: interfaces are deduplicated by UUID (structured unique append).

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — unused (DCE/RPC ops are session-wide)
    source_type — unused
"""

CAP_DCERPC_INTERFACES = 20


def init():
    return {
        "dcerpc_packet_types": set(),
        "dcerpc_interfaces": [],
        "dcerpc_opnums": set(),
    }


def accumulate(s, ex, is_fwd, source_type):
    if ex.get("dcerpc_packet_type"):
        s["dcerpc_packet_types"].add(ex["dcerpc_packet_type"])
    if ex.get("dcerpc_interface_uuid") and len(s["dcerpc_interfaces"]) < CAP_DCERPC_INTERFACES:
        uuid = ex["dcerpc_interface_uuid"]
        name = ex.get("dcerpc_interface_name", "")
        if not any(i["uuid"] == uuid for i in s["dcerpc_interfaces"]):
            s["dcerpc_interfaces"].append({"uuid": uuid, "name": name})
    if ex.get("dcerpc_opnum") is not None:
        s["dcerpc_opnums"].add(ex["dcerpc_opnum"])


def serialize(s):
    s["dcerpc_packet_types"] = sorted(s["dcerpc_packet_types"])
    s["dcerpc_interfaces"] = s["dcerpc_interfaces"][:CAP_DCERPC_INTERFACES]
    s["dcerpc_opnums"] = sorted(s["dcerpc_opnums"])
