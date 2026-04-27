"""
Network workspace schema.

Declares the node- and edge-field catalog that today is implicit in
`frontend/src/core/displayFilter.js` + `FilterBar.jsx`. Phase 2A makes it
explicit; Phase 2B rewrites the frontend evaluator to read from it.

Catalog recovered from the exec plan
(`llm_docs/plans/active/workspace-phase2-execution.md`, tables under
"Implicit schema today"). If you add, remove, or rename anything here,
that's a filter-behavior regression unless matched by an evaluator change.

Notes on wire-name quirks declared schema-side (no core special-casing):
- Host IP filters (`ip`, `ip.src`, `ip.dst`) all dispatch through synthetic
  edge fields `_endpointIps`, `_srcIp`, `_dstIp` populated by the network
  workspace's `enrichEdge` hook in the frontend descriptor. The evaluator
  treats them like any other schema field.
- Flow `port` declares `sources=["src_ports", "dst_ports"]`; the evaluator
  unions the two arrays generically. No port-specific code in core.
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
        name="mac_vendors", display_name="Vendor", filter_path="vendor",
        type="string", multi=True,
        description="MAC OUI vendor lookup for this host.",
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
#
# `_endpointIps`, `_srcIp`, `_dstIp` are synthetic keys populated by the
# network workspace's frontend `enrichEdge` hook — not present on the raw
# edge dict from the backend. They let the generic evaluator dispatch
# `ip` / `ip.src` / `ip.dst` filters on edges without core knowing the
# concept of "host IP." A non-network workspace (e.g. forensic) would
# simply not declare these.

FLOW_FIELDS = [
    Field(
        name="protocol", display_name="Protocol", filter_path="protocol",
        type="protocol",
        description="Top-layer protocol of the flow (HTTPS, DNS, etc.).",
    ),
    Field(
        name="_endpointIps", display_name="IP (either endpoint)", filter_path="ip",
        type="ip", multi=True,
        description="Matches either endpoint IP of the flow. Populated by the workspace `enrichEdge` hook.",
    ),
    Field(
        name="_srcIp", display_name="Source IP", filter_path="ip.src",
        type="ip",
        description="Flow source endpoint IP. Populated by the workspace `enrichEdge` hook.",
    ),
    Field(
        name="_dstIp", display_name="Destination IP", filter_path="ip.dst",
        type="ip",
        description="Flow destination endpoint IP. Populated by the workspace `enrichEdge` hook.",
    ),
    Field(
        name="src_ports", display_name="Port", filter_path="port",
        type="port", multi=True,
        sources=["src_ports", "dst_ports"],
        description="Ports observed on the flow. Union of src_ports and dst_ports.",
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
            # Phase 5.6 (B1): fields the global search bar scans on each host.
            # Match reason shown to the user is the field's display_name.
            searchable_fields=["ips", "macs", "mac_vendors", "hostnames", "os_guess"],
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
            # Phase 5.6 (B1): edge fields scanned by the global search bar.
            # Includes protocol + the EDGE_FIELD_REGISTRY edge_keys whose
            # values are user-relevant strings (TLS / HTTP / DNS / JA3-4).
            # Wire keys that don't have a matching Field show the wire key
            # as the match reason — informative enough for power users.
            searchable_fields=[
                "protocol",
                "tls_snis", "tls_versions", "tls_selected_ciphers", "tls_ciphers",
                "http_hosts", "http_fwd_user_agents",
                "dns_queries",
                "ja3_hashes", "ja4_hashes",
            ],
            description="A bidirectional conversation between two hosts on one protocol.",
        ),
    ],
)
