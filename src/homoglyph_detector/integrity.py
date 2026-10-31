"""Integrity verification for the bundled data files.

data/MANIFEST.json pins the SHA-256 and version of every file in data/. Every read goes through
read_verified(), which refuses (DataIntegrityError) a file that is missing from the manifest or
whose content changed: a security tool must not silently run on tampered brand allow-lists,
Unicode tables or calibration. scripts/seal_data.py regenerates the manifest after a reviewed change.
"""
from __future__ import annotations

import hashlib
import json
from functools import cache
from importlib.resources import files

DATA = files("homoglyph_detector") / "data"
MANIFEST = "MANIFEST.json"


class DataIntegrityError(RuntimeError):
    """Data does not match its pinned SHA-256, or is not pinned at all."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@cache
def manifest() -> dict:
    return json.loads((DATA / MANIFEST).read_text("utf-8"))


def read_verified(name: str) -> str:
    entry = manifest()["files"].get(name)
    if entry is None:
        raise DataIntegrityError(f"data/{name} is not listed in data/{MANIFEST}")
    raw = (DATA / name).read_bytes()
    if sha256(raw) != entry["sha256"]:
        raise DataIntegrityError(f"data/{name} does not match its SHA-256 in data/{MANIFEST}: "
                                 "the file was modified; reinstall, or review it and run scripts/seal_data.py")
    return raw.decode("utf-8")


def verify_all() -> dict[str, str]:
    """Check every bundled data file: {name: 'ok' | error message}."""
    status = {}
    on_disk = {p.name for p in DATA.iterdir() if p.is_file() and p.name != MANIFEST}
    for name in sorted(on_disk | set(manifest()["files"])):
        try:
            read_verified(name)
            status[name] = "ok"
        except (DataIntegrityError, FileNotFoundError) as error:
            status[name] = str(error)
    return status
