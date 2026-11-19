"""Prepare private, time-split samples from independently labeled URLs; never run the detector."""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
import unicodedata
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import date
from importlib.metadata import version
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import unquote

from homoglyph_detector.context import _authority, _psl, _split_port, _url_text, prepare, userinfo_domain

STRATA = ("homoglyph", "typosquat", "combosquat", "userinfo")
LABELS = {*STRATA, "benign", "other_phish"}
SPLITS = ("development", "validation", "holdout")


@dataclass(frozen=True)
class Sample:
    observed_on: str
    domain: str
    label: str
    url: str
    source_length: int


def source_date(value: str) -> date:
    day = date.fromisoformat(value)
    if value != day.isoformat():
        raise ValueError("expected a YYYY-MM-DD date")
    return day


def sample_from_row(row: dict) -> Sample | None:
    if not isinstance(row, dict) or not all(isinstance(row.get(k), str) for k in ("url", "label", "observed_on")):
        raise ValueError("expected url, label and observed_on strings")
    raw, label, day = row["url"], row["label"], source_date(row["observed_on"])
    lure = row.get("userinfo_lure", "")
    if label not in LABELS or not isinstance(lure, str) or (label == "userinfo" and not lure):
        raise ValueError("unknown label or missing reviewed userinfo lure")
    url = _authority(_url_text(unicodedata.normalize("NFC", raw.strip())))
    if url is None or url[0] not in ("http", "https"):
        return None
    scheme, authority = url
    userinfo, at, hostport = authority.rpartition("@")
    raw_host, port = _split_port(hostport)
    ctx = prepare(f"{scheme}://{raw_host}")  # a bad port does not prevent grouping the host
    domain = _psl().privatesuffix(ctx.a_label, accept_unknown=False) if ctx.a_label else None
    if not domain:
        return None
    if lure:
        lure_ctx = prepare(lure)
        shown = prepare(userinfo_domain(unquote(userinfo)))
        if not at or lure != userinfo_domain(lure) or not lure_ctx.a_label or lure_ctx.a_label != shown.a_label:
            raise ValueError("reviewed lure must match the domain shown in userinfo")
        userinfo = lure + "@"
    else:
        userinfo = ""
    if port:
        digits = port.lstrip("0") or "0"
        port = str(min(int(digits), 65536)) if re.fullmatch(r"[0-9]{1,5}", digits) else "invalid"
    # Keep the written host (including percent escapes and invisible characters), so its evidence is not mapped away.
    reduced = f"{scheme}://{userinfo}{raw_host}" + (":" + port if port is not None else "")
    return Sample(day.isoformat(), domain, label, reduced, len(raw))


def prepare_corpus(lines: Iterable[str], validation_start: date, holdout_start: date,
                   per_group: int, coverage_size: int, seed: int) -> tuple[dict, dict]:
    if validation_start >= holdout_start or min(per_group, coverage_size) < 0:
        raise ValueError("expected ordered dates and non-negative sample quotas")
    # ponytail: one record per registered domain in memory; use disk grouping if the input exceeds RAM.
    first: dict[str, Sample] = {}
    labels: dict[str, set[str]] = {}
    counts: Counter[str] = Counter()
    for index, line in enumerate(lines, 1):
        if not line.strip():
            continue
        counts["rows"] += 1
        try:
            sample = sample_from_row(json.loads(line))
        except (ValueError, TypeError, RecursionError):
            raise ValueError(f"invalid labeled input at line {index}") from None
        if sample is None:
            counts["without_registered_domain"] += 1
            continue
        labels.setdefault(sample.domain, set()).add(sample.label)
        previous = first.get(sample.domain)
        if previous:
            counts["duplicate_domain_rows"] += 1
        if previous is None or (sample.observed_on, sample.label, sample.url, sample.source_length) < (
                previous.observed_on, previous.label, previous.url, previous.source_length):
            first[sample.domain] = sample
    samples = sorted(first.values(), key=lambda s: s.domain)
    counts["registered_domains"] = len(samples)
    counts["conflicting_label_domains"] = sum(len(group) > 1 for group in labels.values())
    rng = random.Random(seed)
    positives = [s for s in samples if s.label != "benign"]
    coverage = rng.sample(positives, min(coverage_size, len(positives)))
    reserved = {s.domain for s in coverage}
    chosen = [(s, "benign") for s in samples if s.label == "benign"] + [(s, "coverage") for s in coverage]
    strata = {}
    for label in STRATA:
        available = [s for s in positives if s.label == label and s.domain not in reserved]
        selected = rng.sample(available, min(per_group, len(available)))
        chosen.extend((s, "stratified") for s in selected)
        strata[label] = {"available": len(available), "selected": len(selected), "shortfall": per_group - len(selected)}
    output = {split: [] for split in SPLITS}
    for sample, cohort in sorted(chosen, key=lambda pair: (pair[0].domain, pair[1])):
        day = source_date(sample.observed_on)
        split = "development" if day < validation_start else "validation" if day < holdout_start else "holdout"
        output[split].append({**asdict(sample), "cohort": cohort})
    report = {"counts": dict(counts), "strata": strata, "coverage_shortfall": coverage_size - len(coverage),
              "splits": {split: {"rows": len(rows), "labels": dict(Counter(r["label"] for r in rows)),
                                 "cohorts": dict(Counter(r["cohort"] for r in rows))}
                         for split, rows in output.items()}}
    return output, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="authorized, independently labeled JSONL export")
    parser.add_argument("--output", type=Path, required=True, help="new private output directory; never overwritten")
    parser.add_argument("--source", required=True, help="source version, provenance and permitted use")
    parser.add_argument("--validation-start", type=source_date, required=True)
    parser.add_argument("--holdout-start", type=source_date, required=True)
    parser.add_argument("--per-group", type=int, default=300, help="positive quota per stratum across all splits")
    parser.add_argument("--coverage", type=int, default=500, help="separate random positive-domain sample")
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args(argv)
    digest = hashlib.sha256()

    def lines() -> Iterable[str]:
        with args.input.open("rb") as stream:
            while raw := stream.readline(1_048_577):
                if len(raw) > 1_048_576:
                    raise ValueError("input line exceeds 1 MiB")
                digest.update(raw)
                try:
                    yield raw.decode("utf-8")
                except UnicodeError:
                    raise ValueError("input must be UTF-8") from None

    try:
        if not args.source.strip() or args.output.exists():
            raise ValueError("source is required and output must not exist")
        splits, report = prepare_corpus(lines(), args.validation_start, args.holdout_start,
                                       args.per_group, args.coverage, args.seed)
        manifest = {"schema_version": 1, "source": args.source, "input_sha256": digest.hexdigest(),
                    "runtime": {"python": sys.version.split()[0], "idna": version("idna"),
                                "publicsuffixlist": version("publicsuffixlist")},
                    "validation_start": args.validation_start.isoformat(), "holdout_start": args.holdout_start.isoformat(),
                    "per_group": args.per_group, "coverage": args.coverage, "seed": args.seed, **report, "files": {}}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(prefix=".baseline-", dir=args.output.parent) as staging:
            for split, rows in splits.items():
                name = split + ".jsonl"
                data = "".join(json.dumps(row, sort_keys=True, ensure_ascii=True) + "\n" for row in rows).encode("utf-8")
                (Path(staging) / name).write_bytes(data)
                manifest["files"][name] = {"sha256": hashlib.sha256(data).hexdigest(), "rows": len(rows)}
            (Path(staging) / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                                                       encoding="utf-8", newline="\n")
            Path(staging).rename(args.output)
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0
    except ValueError as error:
        print(f"prepare-baseline: {error}", file=sys.stderr)
    except OSError:
        print("prepare-baseline: cannot read input or create a new output directory", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
