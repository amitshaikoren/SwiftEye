"""
Zeek log ingestion adapters.

Each module handles one Zeek log type and registers itself via @register_adapter.
Import this package from the parent adapters __init__.py to register all Zeek adapters.
"""

from . import conn      # noqa: F401
from . import dns       # noqa: F401
from . import http      # noqa: F401
from . import ssl       # noqa: F401
from . import smb       # noqa: F401
from . import dce_rpc   # noqa: F401
