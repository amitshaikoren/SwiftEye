"""
Parquet ingestion adapter.

Registers ParquetAdapter if pyarrow is installed. If pyarrow is absent the
server starts normally; .parquet uploads will fail with a clear error message
rather than a cryptic ImportError.
"""

try:
    from . import adapter  # noqa: F401
except ImportError:
    import logging
    logging.getLogger("swifteye.adapters").warning(
        "pyarrow not installed — Parquet adapter unavailable. "
        "Install with: pip install pyarrow"
    )
