"""
DCE/RPC session field accumulation.

Custom: interfaces are deduplicated by UUID (structured unique append).
Zeek dce_rpc.log provides operation names and named pipes in addition
to the interface/opnum data from pcap dissection.

Key variables:
    s           — session dict (mutable)
    ex          — pkt.extra from current packet (read-only)
    is_fwd      — unused (DCE/RPC ops are session-wide)
    source_type — "zeek" when from Zeek adapter
"""

from analysis.protocol_fields import cap_list


def init():
    return {
        "dcerpc_packet_types": set(),
        "dcerpc_interfaces": [],
        "dcerpc_opnums": set(),
        "dcerpc_operations": set(),    # Zeek: named operation (e.g. "DRSGetNCChanges")
        "dcerpc_named_pipes": set(),   # Zeek: named pipe (e.g. "\\pipe\\samr")
    }


def accumulate(s, ex, is_fwd, source_type):
    if ex.get("dcerpc_packet_type"):
        s["dcerpc_packet_types"].add(ex["dcerpc_packet_type"])
    if ex.get("dcerpc_interface_uuid"):
        uuid = ex["dcerpc_interface_uuid"]
        name = ex.get("dcerpc_interface_name", "")
        if not any(i["uuid"] == uuid for i in s["dcerpc_interfaces"]):
            s["dcerpc_interfaces"].append({"uuid": uuid, "name": name})
    elif ex.get("dcerpc_interface_name"):
        # Zeek may provide name without UUID — still useful
        name = ex["dcerpc_interface_name"]
        if not any(i.get("name") == name for i in s["dcerpc_interfaces"]):
            s["dcerpc_interfaces"].append({"uuid": "", "name": name})
    if ex.get("dcerpc_opnum") is not None:
        s["dcerpc_opnums"].add(ex["dcerpc_opnum"])
    if ex.get("dcerpc_operation"):
        s["dcerpc_operations"].add(ex["dcerpc_operation"])
    if ex.get("dcerpc_named_pipe"):
        s["dcerpc_named_pipes"].add(ex["dcerpc_named_pipe"])


def serialize(s):
    s["dcerpc_packet_types"] = sorted(s["dcerpc_packet_types"])
    cap_list(s, "dcerpc_interfaces")
    s["dcerpc_opnums"] = sorted(s["dcerpc_opnums"])
    s["dcerpc_operations"] = sorted(s["dcerpc_operations"])
    s["dcerpc_named_pipes"] = sorted(s["dcerpc_named_pipes"])
