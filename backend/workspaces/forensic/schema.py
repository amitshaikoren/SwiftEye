"""
Forensic workspace schema — Phase 5 population.

Node types: process, file, registry, endpoint.
Edge types: spawned (proc→proc), connected (proc→endpoint),
            wrote (proc→file), set_value (proc→registry).

`user` and `host` are metadata fields on process nodes, not separate nodes.
Computer name and username do not generate graph nodes.
"""

from __future__ import annotations

from core.schema import EdgeType, Field, NodeType, WorkspaceSchema

# ---------------------------------------------------------------------------
# Node types
# ---------------------------------------------------------------------------

_PROCESS_FIELDS = [
    Field(name="image",           display_name="Image",           filter_path="image",           type="string"),
    Field(name="command_line",    display_name="Command Line",     filter_path="command_line",    type="string"),
    Field(name="user",            display_name="User",             filter_path="user",            type="string"),
    Field(name="pid",             display_name="PID",              filter_path="pid",             type="int"),
    Field(name="guid",            display_name="Process GUID",     filter_path="guid",            type="string"),
    Field(name="hashes",          display_name="Hashes",           filter_path="hashes",          type="string"),
    Field(name="integrity_level", display_name="Integrity Level",  filter_path="integrity_level", type="string"),
    Field(name="computer",        display_name="Computer",         filter_path="computer",        type="string"),
]

_FILE_FIELDS = [
    Field(name="path",      display_name="Path",      filter_path="path",      type="string"),
    Field(name="extension", display_name="Extension", filter_path="extension", type="string"),
]

_REGISTRY_FIELDS = [
    Field(name="key",   display_name="Registry Key",   filter_path="key",   type="string"),
    Field(name="hive",  display_name="Hive",           filter_path="hive",  type="string"),
]

_ENDPOINT_FIELDS = [
    Field(name="ip",       display_name="IP",       filter_path="ip",       type="ip"),
    Field(name="port",     display_name="Port",      filter_path="port",     type="port"),
    Field(name="hostname", display_name="Hostname",  filter_path="hostname", type="string"),
]

PROCESS_NODE  = NodeType(name="process",  label="Process",  color="#4fc3f7", shape="circle",  label_field="image",  fields=_PROCESS_FIELDS,  description="An executing process observed by Sysmon.")
FILE_NODE     = NodeType(name="file",     label="File",     color="#fff176", shape="diamond", label_field="path",   fields=_FILE_FIELDS,     description="A file system object created or modified by a process.")
REGISTRY_NODE = NodeType(name="registry", label="Registry", color="#ffb74d", shape="square",  label_field="key",    fields=_REGISTRY_FIELDS, description="A registry key modified by a process.")
ENDPOINT_NODE = NodeType(name="endpoint", label="Endpoint", color="#ce93d8", shape="rounded", label_field="ip",     fields=_ENDPOINT_FIELDS, description="A network endpoint contacted by a process.")

# ---------------------------------------------------------------------------
# Edge types
# ---------------------------------------------------------------------------

_SPAWNED_FIELDS = [
    Field(name="command_line",        display_name="Child Command Line",  filter_path="command_line",        type="string"),
    Field(name="parent_command_line", display_name="Parent Command Line", filter_path="parent_command_line", type="string"),
    Field(name="integrity_level",     display_name="Integrity Level",     filter_path="integrity_level",     type="string"),
    Field(name="hashes",              display_name="Hashes",              filter_path="hashes",              type="string"),
]

_CONNECTED_FIELDS = [
    Field(name="protocol",   display_name="Protocol",    filter_path="protocol",   type="protocol"),
    Field(name="local_ip",   display_name="Local IP",    filter_path="local_ip",   type="ip"),
    Field(name="local_port", display_name="Local Port",  filter_path="local_port", type="port"),
]

_WROTE_FIELDS = [
    Field(name="creation_utc_time", display_name="File Creation Time", filter_path="creation_utc_time", type="string"),
    Field(name="hashes",            display_name="Hashes",             filter_path="hashes",            type="string"),
]

_SET_VALUE_FIELDS = [
    Field(name="details",    display_name="Value Written", filter_path="details",    type="string"),
    Field(name="event_type", display_name="Event Type",   filter_path="event_type", type="string"),
]

SPAWNED_EDGE   = EdgeType(name="spawned",   label="Spawned",    color="#4fc3f7", src_type="process", dst_type="process",  fields=_SPAWNED_FIELDS,   description="Parent process spawned child process (EID 1).")
CONNECTED_EDGE = EdgeType(name="connected", label="Connected",  color="#ce93d8", src_type="process", dst_type="endpoint", fields=_CONNECTED_FIELDS, description="Process opened a network connection (EID 3).")
WROTE_EDGE     = EdgeType(name="wrote",     label="Wrote",      color="#fff176", src_type="process", dst_type="file",     fields=_WROTE_FIELDS,     description="Process created or overwrote a file (EID 11).")
SET_VALUE_EDGE = EdgeType(name="set_value", label="Set Value",  color="#ffb74d", src_type="process", dst_type="registry", fields=_SET_VALUE_FIELDS, description="Process set a registry value (EID 13).")

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

FORENSIC_SCHEMA = WorkspaceSchema(
    workspace="forensic",
    node_types=[PROCESS_NODE, FILE_NODE, REGISTRY_NODE, ENDPOINT_NODE],
    edge_types=[SPAWNED_EDGE, CONNECTED_EDGE, WROTE_EDGE, SET_VALUE_EDGE],
)
