"""
Schema negotiation staging area.

When phase-1 inspection finds a mismatch, the uploaded file is moved here
and a token is issued. Phase 2 looks up the token to retrieve the file and
resume ingestion with the user-confirmed mapping.

The staging area is in-memory (dict) — staged files survive as long as the
server process is running. Files are stored in a dedicated temp subdirectory
so they outlive the per-upload temp dir.
"""

import os
import shutil
import tempfile
import uuid
import logging
from pathlib import Path
from typing import Dict, Optional

from .contracts import StagedFile

logger = logging.getLogger("swifteye.schema.staging")

# Module-level staging dir created once on first use
_STAGING_DIR: Optional[Path] = None
_STAGED: Dict[str, StagedFile] = {}  # token → StagedFile


def _get_staging_dir() -> Path:
    global _STAGING_DIR
    if _STAGING_DIR is None or not _STAGING_DIR.exists():
        _STAGING_DIR = Path(tempfile.mkdtemp(prefix="swifteye_schema_staging_"))
        logger.debug("Schema staging dir: %s", _STAGING_DIR)
    return _STAGING_DIR


def stage_file(src_path: Path, adapter_name: str, original_filename: str) -> str:
    """Move a file into the staging area and return a token.

    The caller must NOT delete src_path after calling this — staging owns it.
    """
    token = str(uuid.uuid4())
    staging_dir = _get_staging_dir()
    dest = staging_dir / f"{token}_{Path(original_filename).name}"
    shutil.move(str(src_path), str(dest))

    _STAGED[token] = StagedFile(
        token=token,
        adapter_name=adapter_name,
        original_filename=original_filename,
        staged_path=str(dest),
    )
    logger.info("Staged %s as token %s", original_filename, token)
    return token


def get_staged(token: str) -> Optional[StagedFile]:
    """Look up a staged file by token. Returns None if not found."""
    return _STAGED.get(token)


def clear_staged(token: str) -> None:
    """Delete the staged file and remove from registry."""
    entry = _STAGED.pop(token, None)
    if entry:
        try:
            os.unlink(entry.staged_path)
        except FileNotFoundError:
            pass
        logger.debug("Cleared staged token %s", token)


def list_staged() -> Dict[str, StagedFile]:
    """Return a snapshot of all staged files (for debug/admin)."""
    return dict(_STAGED)
