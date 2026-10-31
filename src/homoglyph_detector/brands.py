"""Brand intelligence database: versioned, validated, integrity-checked brand data, kept out of the code.

    bundled   data/brands.json, pinned by SHA-256 in data/MANIFEST.json
    external  your own databases, same format, from --brands or HOMOGLYPH_BRANDS (os.pathsep-separated);
              'path#sha256=HEX' pins a file to its digest, anything else is loaded as 'unpinned'

Databases merge by brand id, later ones overriding earlier ones (bundled < env < command line).
Validation rejects what would weaken detection, above all a public suffix (github.io, com.vn)
listed as an official domain, which would allow-list every site under it.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from functools import cache
from pathlib import Path

import idna

from .context import _psl
from .integrity import DataIntegrityError, read_verified, sha256

SCHEMA = 1
VERSION = re.compile(r"^\d+\.\d+\.\d+$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
BRAND_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")
KEYWORD = re.compile(r"^[a-z0-9][a-z0-9-]{2,}$")   # ASCII: the visual engine compares against it


class BrandDBError(ValueError):
    """A brand database that fails validation."""


@dataclass(frozen=True)
class BrandDB:
    name: str
    version: str
    updated: str
    sha256: str
    verification: str    # 'manifest' (bundled), 'pinned' (matched a given SHA-256) or 'unpinned'
    source: str          # 'bundled' or the file path
    brands: tuple

    def info(self) -> dict:
        return {k: v for k, v in asdict(self).items() if k != "brands"}


def validate(db: dict, origin: str) -> None:
    """Raise BrandDBError listing every problem in a parsed database."""
    problems = []
    if db.get("schema") != SCHEMA:
        problems.append(f"schema must be {SCHEMA}")
    if not isinstance(db.get("name"), str) or not db["name"].strip():
        problems.append("name is required")
    if not VERSION.match(str(db.get("version", ""))):
        problems.append("version must be MAJOR.MINOR.PATCH")
    if not DATE.match(str(db.get("updated", ""))):
        problems.append("updated must be YYYY-MM-DD")
    brands = db.get("brands")
    if not isinstance(brands, list) or not brands:
        problems.append("brands must be a non-empty list")
        brands = []
    ids, owners = set(), {}
    for i, brand in enumerate(brands):
        where = f"brands[{i}]"
        if not isinstance(brand, dict):
            problems.append(f"{where} must be an object")
            continue
        brand_id = brand.get("id", "")
        where = f"brand '{brand_id}'" if brand_id else where
        if not BRAND_ID.match(str(brand_id)):
            problems.append(f"{where}: id must match {BRAND_ID.pattern}")
        elif brand_id in ids:
            problems.append(f"{where}: duplicate id")
        ids.add(brand_id)
        if not isinstance(brand.get("name"), str) or not brand["name"].strip():
            problems.append(f"{where}: name is required")
        domains, keywords = brand.get("domains"), brand.get("keywords")
        if not isinstance(domains, list) or not domains:
            problems.append(f"{where}: domains must be a non-empty list")
            domains = []
        if not isinstance(keywords, list) or not keywords:
            problems.append(f"{where}: keywords must be a non-empty list")
            keywords = []
        for domain in domains:
            if not isinstance(domain, str) or domain != domain.lower().strip().rstrip("."):
                problems.append(f"{where}: domain {domain!r} must be lower-case, without a trailing dot")
                continue
            try:
                idna.encode(domain)
            except idna.IDNAError as error:
                problems.append(f"{where}: domain '{domain}' is not a valid IDNA2008 name ({error})")
                continue
            if _psl().privatesuffix(domain) is None:
                problems.append(f"{where}: '{domain}' is a public suffix; allow-listing it would trust every site under it")
            if owners.setdefault(domain, brand_id) != brand_id:
                problems.append(f"{where}: domain '{domain}' is already claimed by '{owners[domain]}'")
        for keyword in keywords:
            if not isinstance(keyword, str) or not KEYWORD.match(keyword):
                problems.append(f"{where}: keyword {keyword!r} must be lower-case ASCII [a-z0-9-], 3+ characters")
    if problems:
        raise BrandDBError(f"{origin}: " + "; ".join(problems))


def _parse(raw: str, origin: str) -> dict:
    try:
        db = json.loads(raw)
    except json.JSONDecodeError as error:
        raise BrandDBError(f"{origin}: not valid JSON ({error})") from None
    if not isinstance(db, dict):
        raise BrandDBError(f"{origin}: must be a JSON object")
    validate(db, origin)
    return db


def _db(db: dict, digest: str, verification: str, source: str) -> BrandDB:
    return BrandDB(db["name"], db["version"], db["updated"], digest, verification, source, tuple(db["brands"]))


def bundled() -> BrandDB:
    raw = read_verified("brands.json")   # integrity: SHA-256 pinned in MANIFEST.json
    return _db(_parse(raw, "data/brands.json"), sha256(raw.encode("utf-8")), "manifest", "bundled")


def external(spec: str) -> BrandDB:
    path, _, pin = spec.partition("#sha256=")
    raw = Path(path).read_bytes()
    digest = sha256(raw)
    if pin and pin.strip().lower() != digest:
        raise DataIntegrityError(f"{path}: SHA-256 is {digest}, expected {pin.strip().lower()}")
    return _db(_parse(raw.decode("utf-8"), path), digest, "pinned" if pin else "unpinned", path)


def resolve(files: tuple[str, ...] = ()) -> tuple[str, ...]:
    """Databases to load after the bundled one: HOMOGLYPH_BRANDS first, then `files` (they win)."""
    env = os.environ.get("HOMOGLYPH_BRANDS", "")
    return tuple(s for s in env.split(os.pathsep) if s) + tuple(files)


@cache
def load(files: tuple[str, ...] = ()) -> tuple[list[dict], tuple[BrandDB, ...]]:
    """Merged brand list (later databases override by id) and the databases it came from."""
    dbs = (bundled(), *(external(spec) for spec in files))
    merged: dict[str, dict] = {}
    for db in dbs:
        for brand in db.brands:
            merged[brand["id"]] = brand
    owners: dict[str, str] = {}
    for brand in merged.values():
        for domain in brand["domains"]:
            if owners.setdefault(domain, brand["id"]) != brand["id"]:
                raise BrandDBError(f"domain '{domain}' is claimed by both '{owners[domain]}' and '{brand['id']}'")
    return list(merged.values()), dbs


def load_brands(files: tuple[str, ...] = ()) -> list[dict]:
    return load(resolve(tuple(files)))[0]
