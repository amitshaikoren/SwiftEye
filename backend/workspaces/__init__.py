"""
SwiftEye workspaces — data-domain packs.

Importing this package triggers registration of each bundled workspace.
To add a new workspace, create `backend/workspaces/<name>/` with an
`__init__.py` that calls `core.workspace.register(...)`, then import it here.
"""

from . import network    # noqa: F401  — side-effect: registers NetworkWorkspace
from . import forensic   # noqa: F401  — side-effect: registers ForensicWorkspace (Phase 3 skeleton)
