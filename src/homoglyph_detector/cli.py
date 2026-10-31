"""Command line: homoglyph-detector INPUT... [-f FILE] [--json] [--brands FILE[#sha256=HEX]]... [--verify]"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .analyzer import Report, analyze
from .brands import BrandDBError, load, resolve
from .integrity import DataIntegrityError, verify_all
from .unicode_data import data_versions, is_default_ignorable

ICON = {"SAFE": "✅", "SUSPICIOUS": "⚠\ufe0f ", "MALICIOUS": "🚨"}
EXIT = {"SAFE": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
DATA_ERROR = 3   # tampered, unpinned-but-required or invalid data: refuse to give a verdict


def visible(text: str) -> str:
    """Show hidden/bidi characters as <U+XXXX> so attacker input cannot reorder the report."""
    return "".join(f"<U+{ord(ch):04X}>" if is_default_ignorable(ch) else ch for ch in text)


def render(report: Report) -> str:
    lines = [f"{ICON[report.verdict]} {report.verdict:<10} {visible(report.input)}  [{report.input_type}]"]
    if report.target != report.input:
        lines.append(f"    decoded : {visible(report.target)}")
    if report.a_label and report.a_label not in (report.target, report.input.strip().lower()):
        lines.append(f"    a-label : {report.a_label}")
    lines.append(f"    skeleton: {report.skeleton}")
    lines.append(f"    level   : {report.restriction_level}")
    engines = "  ".join(f"{name} {score:.2f}" for name, score in report.engine_scores.items())
    lines.append(f"    risk    : {report.risk_score}/100   engines: {engines}")
    lines += [f"    - [{f.engine}/{f.severity}] {visible(f.message)}" for f in report.findings]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="homoglyph-detector",
        description="Detect look-alike (homoglyph) domains, emails, URLs and names.",
        epilog="Exit code: 0 all safe, 1 something suspicious, 2 something malicious, "
               "3 data failed integrity or validation checks (no verdict given).",
    )
    parser.add_argument("inputs", nargs="*", help="domains, emails, URLs or names")
    parser.add_argument("-f", "--file", help="read one input per line ('-' for stdin)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    parser.add_argument("--brands", action="append", default=[], metavar="FILE[#sha256=HEX]",
                        help="extra brand database, merged over the bundled one; repeatable. "
                             "'#sha256=HEX' pins it to its digest")
    parser.add_argument("--verify", action="store_true",
                        help="verify the integrity of all bundled data and brand databases, then exit")
    parser.add_argument("--version", action="store_true", help="show versions of the tool and its data")
    args = parser.parse_args(argv)
    try:
        return _run(parser, args)
    except (DataIntegrityError, BrandDBError, OSError) as error:
        print(f"homoglyph-detector: data error: {error}", file=sys.stderr)
        return DATA_ERROR


def _run(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    brand_files = tuple(args.brands)
    if args.verify or args.version:
        status = verify_all() if args.verify else {}
        for name, result in status.items():
            print(f"{'ok  ' if result == 'ok' else 'FAIL'} data/{name}{'' if result == 'ok' else ': ' + result}")
        if any(result != "ok" for result in status.values()):
            return DATA_ERROR
        if args.version:
            unicode_versions = ", ".join(sorted(set(map(str, data_versions().values()))))
            print(f"homoglyph-detector {__version__} (Unicode data {unicode_versions})")
        for db in load(resolve(brand_files))[1]:
            print(f"brands: {db.name} {db.version} ({db.updated}) sha256 {db.sha256[:16]}... "
                  f"[{db.verification}] {db.source}")
        return 0

    inputs = list(args.inputs)
    if args.file:
        stream = sys.stdin if args.file == "-" else open(args.file, encoding="utf-8")
        with stream:
            inputs += [line.strip() for line in stream if line.strip() and not line.startswith("#")]
    if not inputs:
        parser.error("give at least one input or --file")

    for db in load(resolve(brand_files))[1]:
        if db.verification == "unpinned":
            print(f"homoglyph-detector: warning: brand database {db.source} is not pinned; "
                  f"add '#sha256={db.sha256}' to trust exactly this version", file=sys.stderr)
    reports = [analyze(item, brand_files) for item in inputs]
    if args.json:
        print(json.dumps([r.to_dict() for r in reports], ensure_ascii=False, indent=2))
    else:
        print("\n\n".join(render(r) for r in reports))
    return max(EXIT[r.verdict] for r in reports)
