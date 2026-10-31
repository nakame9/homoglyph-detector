#!/usr/bin/env python3
"""Refresh the official Unicode data files in src/homoglyph_detector/data/.

    python scripts/update_unicode_data.py                    # latest release from unicode.org
    python scripts/update_unicode_data.py --version 18.0.0   # a specific release
    python scripts/update_unicode_data.py --base file:///path/to/Public/   # local mirror

Every file is downloaded first and must report the same Unicode version; nothing is
written otherwise, so a failed or mixed-version download never leaves partial data.
Run the test suite afterwards: tests/test_unicode_data.py is the compatibility check.
"""
from __future__ import annotations

import argparse
import re
import sys
import urllib.request
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "src" / "homoglyph_detector" / "data"

# written file -> (path under the Unicode "Public/" directory, property to keep; None = whole file)
FILES = {
    "confusables.txt": ("{security}/confusables.txt", None),
    "IdentifierStatus.txt": ("{security}/IdentifierStatus.txt", None),
    "Scripts.txt": ("{ucd}/Scripts.txt", None),
    "ScriptExtensions.txt": ("{ucd}/ScriptExtensions.txt", None),
    "ScriptAliases.txt": ("{ucd}/PropertyValueAliases.txt", "sc"),
    "DefaultIgnorable.txt": ("{ucd}/DerivedCoreProperties.txt", "Default_Ignorable_Code_Point"),
    "BidiControl.txt": ("{ucd}/PropList.txt", "Bidi_Control"),
}


def version_of(text: str) -> str | None:
    match = re.search(r"Version: (\d+\.\d+\.\d+)|-(\d+\.\d+\.\d+)\.txt", text[:1000])
    return match and (match[1] or match[2])


def keep_property(text: str, prop: str, source: str) -> str:
    lines = text.splitlines()
    header = [line for line in lines[:5] if line.startswith("#")]
    rows = [line for line in lines
            if not line.startswith("#") and prop in [f.strip() for f in line.split("#")[0].split(";")[:2]]]
    if not rows:
        raise ValueError(f"no '{prop}' entries in {source}: has the file format changed?")
    return "\n".join(header + [f"# Only the '{prop}' entries of {source}, extracted by",
                               "# scripts/update_unicode_data.py.", ""] + rows) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", default="latest", help="Unicode version, e.g. 18.0.0 (default: latest)")
    parser.add_argument("--base", default="https://www.unicode.org/Public/", help="mirror of Unicode's Public/")
    args = parser.parse_args(argv)

    base = args.base.rstrip("/") + "/"
    ucd = "UCD/latest/ucd" if args.version == "latest" else f"{args.version}/ucd"
    security = f"security/{args.version}"

    downloaded, versions = {}, {}
    for name, (template, prop) in FILES.items():
        url = base + template.format(ucd=ucd, security=security)
        print(f"fetch {url}")
        with urllib.request.urlopen(url, timeout=60) as response:
            text = response.read().decode("utf-8")
        versions[name] = version_of(text)
        downloaded[name] = keep_property(text, prop, url.rsplit("/", 1)[-1]) if prop else text

    if None in versions.values() or len(set(versions.values())) != 1:
        print(f"error: files disagree on the Unicode version, nothing written: {versions}", file=sys.stderr)
        return 1
    for name, text in downloaded.items():
        (DATA / name).write_text(text, encoding="utf-8")
    print(f"wrote {len(downloaded)} files for Unicode {versions['confusables.txt']} to {DATA}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
