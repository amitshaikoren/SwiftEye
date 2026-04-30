"""
SwiftEye workspaces — data-domain packs.

Importing this package triggers registration of each bundled workspace.
To add a new workspace, create `backend/workspaces/<name>/` with an
`__init__.py` that calls `core.workspace.register(...)`, then import it here.

Worker-process guard: parallel reader workers import this package as a side
effect of their module path (workspaces.network.parser.*). Workers don't need
workspace registration — guard to prevent the registration cascade from
running 8× per parse.
"""

import multiprocessing as _mp

if _mp.current_process().name == 'MainProcess':
    from . import network    # noqa: F401  — side-effect: registers NetworkWorkspace
    from . import forensic   # noqa: F401  — side-effect: registers ForensicWorkspace
