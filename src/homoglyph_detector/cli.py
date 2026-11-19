"""Command line: homoglyph-detector INPUT... [-f FILE] [--json] [--brands FILE[#sha256=HEX]]...
                [--profile NAME | --max-fpr S,M] [--profiles] [--verify] [--version]"""
from __future__ import annotations

import argparse
import json
import os
import sys
import unicodedata
from collections.abc import Iterator
from itertools import islice
from typing import TextIO

from . import __version__
from .analyzer import Report, analyze
from .brands import BrandDBError, load, resolve
from .context import MAX_RAW_LENGTH
from .integrity import DataIntegrityError, verify_all
from .scoring import calibration, custom_profile, profile
from .unicode_data import data_versions, is_default_ignorable

ICON = {"SAFE": "✅", "SUSPICIOUS": "⚠\ufe0f ", "MALICIOUS": "🚨"}
EXIT = {"SAFE": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
DATA_ERROR = 3   # invalid data or resource limit: refuse to give a verdict
CLOSED_PIPE = 128 + 13   # the output's reader went away (SIGPIPE); outside the 0-3 verdict contract
MAX_BATCH_INPUTS = 256
MAX_BATCH_CHARACTERS = 65_536


class BatchLimitError(ValueError):
    """The complete batch cannot be processed within the resource budget."""


def unsafe(ch: str) -> bool:
    """A character a terminal acts on or does not show: controls (C0 such as ESC, CR, LF; DEL; C1 such as CSI),
    format characters (bidi, zero-width, tags), line and paragraph separators, any default-ignorable."""
    return unicodedata.category(ch) in {"Cc", "Cf", "Zl", "Zp"} or is_default_ignorable(ch)


def visible(text: str) -> str:
    """Show unsafe characters as <U+XXXX> so attacker input cannot drive the terminal or reorder the report."""
    return "".join(f"<U+{ord(ch):04X}>" if unsafe(ch) else ch for ch in text)


def json_text(data: object) -> str:
    """JSON that stays human readable (non-ASCII as is) but carries no live unsafe character: those become
    \\uXXXX escapes, so json.loads gives back exactly the same values. Raw newlines only come from the indent."""
    text = json.dumps(data, ensure_ascii=False, indent=2)
    return "".join(json.dumps(ch)[1:-1] if ch != "\n" and unsafe(ch) else ch for ch in text)


def render(report: Report) -> str:
    """The text report; every field that comes from the input or a brand database goes through visible()."""
    shown_input = "<input omitted>" if report.parse_reason == "too_long" else visible(report.input)
    lines = [f"{ICON[report.verdict]} {report.verdict:<10} {shown_input}  [{report.input_type}]"]
    if report.target != report.input:
        lines.append(f"    decoded : {visible(report.target)}")
    if report.a_label and report.a_label not in (report.target, report.input.strip().lower()):
        lines.append(f"    a-label : {visible(report.a_label)}")
    lines.append(f"    skeleton: {visible(report.skeleton)}")
    lines.append(f"    level   : {report.restriction_level}")
    engines = "  ".join(f"{name} {score:.2f}" for name, score in report.engine_scores.items())
    lines.append(f"    risk    : {report.risk_score}/100   engines: {engines}")
    if report.parse_status != "ok":
        lines.append(f"    parse   : {report.parse_status} ({report.parse_reason}): destination not scored")
    if report.probability_at_base_rate is not None:
        lines.append(f"    at base rate {report.base_rate:g}: P(attack) = {report.probability_at_base_rate:.4f}")
    lines.append(f"    profile : {report.profile} (SUSPICIOUS >= {report.thresholds['suspicious']:.2f}, "
                 f"MALICIOUS >= {report.thresholds['malicious']:.2f})")
    shown = {"unicode_confusable": "unicode", "visual_similarity": "visual", "brand_impersonation": "brand",
             "protocol": "idna"}
    parts = [f"{short} {report.evidence.get(key, '-')}" for key, short in shown.items()]
    if "brand_basis" in report.evidence:
        parts[2] += f" (basis: {report.evidence['brand_basis']})"
    lines.append(f"    evidence: {',  '.join(parts)}")
    if report.verdict_note:
        lines.append(f"    note    : {report.verdict_note}")
    lines += [f"    - [{f.engine}/{f.severity}{', ' + f.detail['basis'] if 'basis' in f.detail else ''}] "
              f"{visible(f.message)}" for f in report.findings]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="homoglyph-detector",
        description="Detect look-alike (homoglyph) domains, emails, URLs and names.",
        epilog="Exit code: 0 all safe, 1 something suspicious, 2 something malicious, "
               "3 data failed validation or the batch exceeded a limit (no verdict given).",
    )
    parser.add_argument("inputs", nargs="*", help="domains, emails, URLs or names")
    parser.add_argument("-f", "--file", help="read one input per line ('-' for stdin)")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="print the complete JSON report instead of text")
    output.add_argument("--integration-json", action="store_true", help="print redacted integration JSON (schema v1)")
    parser.add_argument("--brands", action="append", default=[], metavar="FILE[#sha256=HEX]",
                        help="extra brand database, merged over the bundled one; repeatable. "
                             "'#sha256=HEX' pins it to its digest")
    parser.add_argument("--profile", metavar="NAME",
                        help="risk profile for the verdict thresholds: default, banking, browser "
                             "(default: $HOMOGLYPH_PROFILE or 'default'); see --profiles")
    parser.add_argument("--max-fpr", metavar="S,M",
                        help="your own alert budget instead of a profile: the false positive rates accepted "
                             "for SUSPICIOUS and MALICIOUS, e.g. 0.01,0.001")
    parser.add_argument("--base-rate", type=float, metavar="R",
                        help="share of attacks in your traffic (e.g. 0.001): also reports the probability "
                             "corrected to it; the verdict still follows the profile")
    parser.add_argument("--profiles", action="store_true", help="list the risk profiles with their measured rates")
    parser.add_argument("--verify", action="store_true",
                        help="verify the integrity of all bundled data and brand databases, then exit")
    parser.add_argument("--version", action="store_true", help="show versions of the tool and its data")
    args = parser.parse_args(argv)
    try:
        return _run(parser, args)
    except BrokenPipeError:   # the reader closed the pipe ('... | head -1'): not a data error
        try:   # stop the interpreter from flushing into the closed pipe again on exit
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError):
            pass
        return CLOSED_PIPE
    except (DataIntegrityError, BrandDBError, BatchLimitError, OSError) as error:
        print(f"homoglyph-detector: data error: {visible(str(error))}", file=sys.stderr)
        return DATA_ERROR


def _policy(parser: argparse.ArgumentParser, args: argparse.Namespace) -> dict:
    try:
        if args.max_fpr:
            if args.profile:
                parser.error("use either --profile or --max-fpr, not both")
            suspicious, malicious = (float(x) for x in args.max_fpr.split(","))
            return custom_profile(suspicious, malicious)
        return profile(args.profile)
    except ValueError as error:   # bad numbers, unknown profile, inverted budgets
        parser.error(f"invalid risk policy: {error}")


def _list_profiles() -> int:
    for name, pr in calibration()["profiles"].items():
        print(f"{name}: SUSPICIOUS >= {pr['suspicious']:.4f}, MALICIOUS >= {pr['malicious']:.4f}")
        print(f"    {pr['description']}")
        for level in ("suspicious", "malicious"):
            m = pr["test"][level]
            print(f"    {level:<10} recall {m['recall']:.3f}, {m['false_alerts_per_10k']} false alerts "
                  "per 10,000 benign domains (benchmark test split)")
    return 0


def _file_inputs(stream: TextIO, remaining_characters: int) -> Iterator[str]:
    read_size = MAX_RAW_LENGTH + 2  # leave room for a CRLF after a maximum-length input

    def read_chunk() -> str:
        nonlocal remaining_characters
        chunk = stream.readline(min(read_size, remaining_characters + 1))
        remaining_characters -= len(chunk)
        if remaining_characters < 0:
            raise BatchLimitError(f"batch exceeds {MAX_BATCH_CHARACTERS} Unicode characters; split the batch")
        return chunk

    while line := read_chunk():
        comment = line.startswith("#")
        item = line.removesuffix("\n").removesuffix("\r")
        if len(item) > MAX_RAW_LENGTH:
            # Drain the rest before processing the next line. The bounded prefix only triggers the shared guard.
            while line and not line.endswith("\n"):
                line = read_chunk()
            if not comment:
                yield item
        elif not comment and (item := item.strip()):
            yield item


def _run(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    brand_files = tuple(args.brands)
    if args.profiles:
        return _list_profiles()
    policy = _policy(parser, args)
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
            print(visible(f"brands: {db.name} {db.version} ({db.updated}) sha256 {db.sha256[:16]}... "
                          f"[{db.verification}] {db.source}"))
        return 0

    inputs = args.inputs
    if len(inputs) > MAX_BATCH_INPUTS:
        raise BatchLimitError(f"batch exceeds {MAX_BATCH_INPUTS} inputs; split the batch")
    remaining = MAX_BATCH_CHARACTERS - sum(map(len, inputs))
    if remaining < 0:
        raise BatchLimitError(f"batch exceeds {MAX_BATCH_CHARACTERS} Unicode characters; split the batch")
    if args.file:
        stream = sys.stdin if args.file == "-" else open(args.file, encoding="utf-8")
        with stream:
            inputs.extend(islice(_file_inputs(stream, remaining), MAX_BATCH_INPUTS - len(inputs) + 1))
        if len(inputs) > MAX_BATCH_INPUTS:
            raise BatchLimitError(f"batch exceeds {MAX_BATCH_INPUTS} inputs; split the batch")
    if not inputs:
        parser.error("give at least one input or --file")

    for db in load(resolve(brand_files))[1]:
        if db.verification == "unpinned":
            print(f"homoglyph-detector: warning: brand database {visible(db.source)} is not pinned; "
                  f"add '#sha256={db.sha256}' to trust exactly this version", file=sys.stderr)
    if args.base_rate is not None and not 0 < args.base_rate < 1:
        parser.error("--base-rate must be strictly between 0 and 1")
    reports = [analyze(item, brand_files, policy, args.base_rate) for item in inputs]
    if args.integration_json:
        print(json_text([r.to_integration_dict() for r in reports]))
    elif args.json:
        print(json_text([r.to_dict() for r in reports]))
    else:
        print("\n\n".join(render(r) for r in reports))
    return max(EXIT[r.verdict] for r in reports)
