"""Command line: homoglyph-detector INPUT... [-f FILE] [--json] [--brands FILE]"""
from __future__ import annotations

import argparse
import json
import sys

from .analyzer import Report, analyze

ICON = {"SAFE": "✅", "SUSPICIOUS": "⚠️ ", "MALICIOUS": "🚨"}
EXIT = {"SAFE": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}


def render(report: Report) -> str:
    lines = [f"{ICON[report.verdict]} {report.verdict:<10} {report.input}  [{report.input_type}]"]
    if report.target != report.input:
        lines.append(f"    decoded : {report.target}")
    lines.append(f"    skeleton: {report.skeleton}")
    lines.append(f"    level   : {report.restriction_level}")
    lines += [f"    - [{f.severity}] {f.message}" for f in report.findings]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="homoglyph-detector",
        description="Detect look-alike (homoglyph) domains, emails, URLs and names.",
        epilog="Exit code: 0 all safe, 1 something suspicious, 2 something malicious.",
    )
    parser.add_argument("inputs", nargs="*", help="domains, emails, URLs or names")
    parser.add_argument("-f", "--file", help="read one input per line ('-' for stdin)")
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    parser.add_argument("--brands", help="custom brands.json (same format as the bundled one)")
    args = parser.parse_args(argv)

    inputs = list(args.inputs)
    if args.file:
        stream = sys.stdin if args.file == "-" else open(args.file, encoding="utf-8")
        with stream:
            inputs += [line.strip() for line in stream if line.strip() and not line.startswith("#")]
    if not inputs:
        parser.error("give at least one input or --file")

    reports = [analyze(item, args.brands) for item in inputs]
    if args.json:
        print(json.dumps([r.to_dict() for r in reports], ensure_ascii=False, indent=2))
    else:
        print("\n\n".join(render(r) for r in reports))
    return max(EXIT[r.verdict] for r in reports)
