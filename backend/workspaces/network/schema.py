"""
Network workspace schema.

Declares the node- and edge-field catalog that today is implicit in
`frontend/src/core/displayFilter.js` + `FilterBar.jsx`. Phase 2A makes it
explicit; Phase 2B rewrites the frontend evaluator to read from it.

Catalog recovered from the exec plan
(`llm_docs/plans/active/workspace-phase2-execution.md`, tables under
"Implicit schema today"). If you add, remove, or rename anything here,
that's a filter-behavior regression unless matched by an evaluator change.

Notes on wire-name quirks preserved from the current implementation:
- Host `ip` filter also accepts `ip.src` / `ip.dst` as directional variants;
  the underlying wire key is `ips` (array). Handled in the 2B evaluator.
- Flow `port` matches either `src_ports` or `dst_ports` (OR). `name` below
  records the primary wire key — the evaluator OR's both arrays.
"""

from __future__ import annotations

from core.schema import EdgeType, Field, NodeType, WorkspaceSchema


# ── Host (node) fields ────────────────────────────────────────────────────────

HOST_FIELDS = [
    Field(
        name="ips", display_name="IP", filter_path="ip",
        type="ip", multi=True,
        description="Host IP addresses. Also filterable directionally via `ip.src` / `ip.dst`.",
    ),
    Field(
        name="macs", display_name="MAC", filter_path="mac",
        type="mac", multi=True,
        description="Hardware addresses observed for this host.",
    ),
    Field(
        name="hostnames", display_name="Hostname", filter_path="hostname",
        type="string", multi=True,
        description="DNS / mDNS / NetBIOS names resolved to this host.",
    ),
    Field(
        name="protocols", display_name="Protocols", filter_path="protocol",
        type="protocol", multi=True,
        description="Application protocols this host participated in.",
    ),
    Field(
        name="total_bytes", display_name="Bytes", filter_path="bytes",
        type="int",
        description="Total bytes to/from this host across all flows.",
    ),
    Field(
        name="packet_count", display_name="Packets", filter_path="packets",
        type="int",
        description="Total packet count to/from this host.",
    ),
    Field(
        name="os_guess", display_name="OS", filter_path="os",
        type="string", renderer="os_fingerprint",
        description="Passive OS fingerprint (TTL + TCP option heuristics).",
    ),
    Field(
        name="plugin_data.network_role.role", display_name="Role", filter_path="role",
        type="enum", renderer="network_role", bare_flag="gateway",
        description="Inferred network role (gateway / client / server / peer). Bare `gateway` matches role=gateway.",
    ),
    Field(
        name="is_private", display_name="Private", filter_path="private",
        type="bool", bare_flag="private",
        description="True if the host IP is in RFC1918 private space. Bare `private` matches true.",
    ),
    Field(
        name="is_subnet", display_name="Subnet group", filter_path="subnet",
        type="bool", bare_flag="subnet",
        description="True for subnet-aggregate nodes. Bare `subnet` matches true.",
    ),
]


# ── Flow (edge) fields ────────────────────────────────────────────────────────

FLOW_FIELDS = [
    Field(
        name="protocol", display_name="Protocol", filter_path="protocol",
        type="protocol",
        description="Top-layer protocol of the flow (HTTPS, DNS, etc.).",
    ),
    Field(
        name="src_ports", display_name="Port", filter_path="port",
        type="port", multi=True,
        description="Ports observed on the flow. Evaluator OR's `src_ports` and `dst_ports`.",
    ),
    Field(
        name="total_bytes", display_name="Bytes", filter_path="bytes",
        type="int",
        description="Total bytes transferred over the flow.",
    ),
    Field(
        name="packet_count", display_name="Packets", filter_path="packets",
        type="int",
        description="Packet count for the flow.",
    ),
    Field(
        name="tls_snis", display_name="TLS SNI", filter_path="tls.sni",
        type="string", multi=True,
        description="Server Name Indication values seen in TLS ClientHello.",
    ),
    Field(
        name="http_hosts", display_name="HTTP Host", filter_path="http.host",
        type="string", multi=True,
        description="HTTP Host header values on cleartext HTTP.",
    ),
    Field(
        name="dns_queries", display_name="DNS", filter_path="dns",
        type="string", multi=True,
        description="DNS QNAMEs carried in the flow.",
    ),
]


# ── Assembled schema ──────────────────────────────────────────────────────────

NETWORK_SCHEMA = WorkspaceSchema(
    workspace="network",
    node_types=[
        NodeType(
            name="host",
            label="Host",
            color="#3b82f6",
            shape="circle",
            label_field="ips",
            fields=HOST_FIELDS,
            description="A network endpoint identified by one or more IP addresses.",
        ),
    ],
    edge_types=[
        EdgeType(
            name="flow",
            label="Flow",
            color="#94a3b8",
            src_type="host",
            dst_type="host",
            fields=FLOW_FIELDS,
            description="A bidirectional conversation between two hosts on one protocol.",
        ),
    ],
)
