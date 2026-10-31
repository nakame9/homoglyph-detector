#!/usr/bin/env python3
"""Pin every file in src/homoglyph_detector/data/ in MANIFEST.json (SHA-256 + version).

    python scripts/seal_data.py           # after a reviewed change to the data
    python scripts/seal_data.py --check   # exit 1 if the manifest is out of date (CI)

Refuses to seal a brands.json that fails validation, or whose content changed while its
'version' did not go up: every change to the brand database must carry a new version.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "src" / "homoglyph_detector" / "data"
MANIFEST = DATA / "MANIFEST.json"
sys.path.insert(0, str(ROOT / "src"))
from homoglyph_detector.brands import BrandDBError, validate  # noqa: E402


def version_of(name: str, text: str) -> str | None:
    if name == "brands.json":
        return json.loads(text)["version"]
    if name == "calibration.json":
        return None   # pinned through the dataset and brand database it records
    match = re.search(r"Version: (\d+\.\d+\.\d+)|-(\d+\.\d+\.\d+)\.txt", text[:1000])
    return match and (match[1] or match[2])


def semver(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="only check that MANIFEST.json is current")
    args = parser.parse_args(argv)

    before = json.loads(MANIFEST.read_text("utf-8"))["files"] if MANIFEST.exists() else {}
    files = {}
    for path in sorted(p for p in DATA.iterdir() if p.is_file() and p != MANIFEST):
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        version = version_of(path.name, raw.decode("utf-8"))
        if path.name == "brands.json":
            try:
                validate(json.loads(raw), "brands.json")
            except BrandDBError as error:
                print(f"error: {error}", file=sys.stderr)
                return 1
            old = before.get("brands.json")
            if old and old["sha256"] != digest and semver(version) <= semver(old["version"]):
                print(f"error: brands.json changed but its version {version} is not above {old['version']}: "
                      "bump 'version' (and 'updated') first", file=sys.stderr)
                return 1
        files[path.name] = {"sha256": digest, "version": version, "bytes": len(raw)}

    text = json.dumps({"schema": 1, "files": files}, indent=2) + "\n"
    if args.check:
        if not MANIFEST.exists() or MANIFEST.read_text("utf-8") != text:
            print("error: data/MANIFEST.json is out of date: review the data change and run scripts/seal_data.py",
                  file=sys.stderr)
            return 1
        print(f"MANIFEST.json is current ({len(files)} files)")
        return 0
    MANIFEST.write_text(text, encoding="utf-8")
    print(f"sealed {len(files)} files in {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
