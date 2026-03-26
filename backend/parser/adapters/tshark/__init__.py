"""
Tshark CSV export ingestion adapters.

Each module handles one tshark field export format and registers itself
via @register_adapter. Import this package from the parent adapters
__init__.py to register all tshark adapters.
"""

from . import arp  # noqa: F401
