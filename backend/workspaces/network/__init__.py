"""
NetworkWorkspace — SwiftEye's original and (in Phase 1) only workspace.

Registers itself on import. Phase 1 = pure relocation, so this workspace
currently does little more than exist; Phase 2 wires up schema, and Phase 3
introduces the workspace selector that toggles between network and forensic.
"""

from core.schema import WorkspaceSchema
from core.workspace import Workspace, register
from workspaces.network.schema import NETWORK_SCHEMA
from workspaces.network.analysis.sessions import SESSION_CORE_CATALOG
from workspaces.network.analysis.protocol_fields import all_protocol_catalogs


class NetworkWorkspace(Workspace):
    name = "network"
    # Domain label only — the workspace accepts multiple ingestion adapters
    # (pcap, Zeek, NetFlow, …). Format names belong on adapters, not here.
    label = "Network"

    def activate(self) -> None:
        # Phase 1: no per-activation wiring needed — the network code still
        # imports its own dependencies eagerly. Will tighten in Phase 2.
        return None

    @property
    def schema(self) -> WorkspaceSchema:
        return NETWORK_SCHEMA

    def query_session_groups(self) -> list:
        return [{"group": "core", "fields": SESSION_CORE_CATALOG}] + all_protocol_catalogs()


register(NetworkWorkspace())
