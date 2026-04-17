"""
SwiftEye engine — workspace-agnostic core.

Contains the pluggable-workspace framework, generic storage + algorithms,
HTTP routes, and anything else that does not bind to a specific data domain.

Workspace-specific code (network, forensic, ...) lives under
`backend/workspaces/<name>/` and registers itself with the registry in
`core.workspace`.

See `llm_docs/plans/active/forensic-workspace.md` for the overall plan.
"""
