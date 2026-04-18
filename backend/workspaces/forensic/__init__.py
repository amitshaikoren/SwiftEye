"""
ForensicWorkspace — Phase 3 skeleton.

Registers itself on import. No adapters, no plugins, no charts, and an
empty schema. Enough for the engine to boot with the workspace active so
that Phase 3's workspace selector can flip to it and the frontend can
render a loaded-but-empty workspace shell.

Phases 4+ flesh this out: Phase 4 = EVTX reader + Sysmon dissectors,
Phase 5 = full forensic schema + action aggregator, Phase 6+ = research
charts and plugins. See `llm_docs/plans/active/forensic-workspace.md`.
"""

from core.schema import WorkspaceSchema
from core.workspace import Workspace, register
from workspaces.forensic.schema import FORENSIC_SCHEMA


class ForensicWorkspace(Workspace):
    name = "forensic"
    label = "Forensic"

    def activate(self) -> None:
        # Skeleton: nothing to wire up yet.
        return None

    @property
    def schema(self) -> WorkspaceSchema:
        return FORENSIC_SCHEMA


register(ForensicWorkspace())
