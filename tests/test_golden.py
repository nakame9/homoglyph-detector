"""Golden test corpus: hand-labelled cases for the 10 required groups, plus a regression snapshot.

tests/golden/corpus.jsonl   input, group, label (attack / benign / null), optional host, known_issue
tests/golden/snapshot.jsonl the reviewed output for every corpus input under every risk profile

The labels say what a case *is*, never what the tool happens to answer. A wrong answer that is
accepted for now carries `known_issue` and runs as a strict xfail, so fixing it is noticed.
After an intended behaviour change, review the diff and regenerate the snapshot:

    UPDATE_GOLDEN=1 pytest tests/test_golden.py
"""
import json
import os
import time
from pathlib import Path

import pytest

from homoglyph_detector import analyze
from homoglyph_detector.context import prepare
from homoglyph_detector.scoring import calibration

GOLDEN = Path(__file__).resolve().parent / "golden"
CORPUS = [json.loads(line) for line in (GOLDEN / "corpus.jsonl").read_text("utf-8").splitlines()]
SNAPSHOT = GOLDEN / "snapshot.jsonl"
GROUPS = ["ascii_lookalike", "cyrillic_greek_homoglyph", "mixed_script", "punycode_malformed", "zero_width",
          "bidi_override", "vietnamese", "multilingual_legit", "multi_level_suffix", "url_edge"]
IDS = [f"{case['group']}:{case['input'].encode('unicode_escape').decode()}" for case in CORPUS]


def kinds(report) -> set[str]:
    return {f.kind for f in report.findings}


def test_corpus_covers_every_required_group():
    counts = {group: sum(case["group"] == group for case in CORPUS) for group in GROUPS}
    assert set(counts) == {case["group"] for case in CORPUS}
    assert all(n >= 5 for n in counts.values()), counts


@pytest.mark.parametrize("case", CORPUS, ids=IDS)
def test_label(case):
    if case["label"] is None:
        analyze(case["input"])          # behaviour-only case: must not crash
        return
    if "known_issue" in case:
        pytest.xfail(case["known_issue"])
    report = analyze(case["input"])
    assert (report.verdict != "SAFE") == (case["label"] == "attack"), (report.verdict, sorted(kinds(report)))


@pytest.mark.parametrize("case", [c for c in CORPUS if "known_issue" in c], ids=lambda c: c["input"])
def test_known_issues_are_still_issues(case):
    """Strict counterpart of the xfails above: when one gets fixed, drop its known_issue."""
    flagged = analyze(case["input"]).verdict != "SAFE"
    assert flagged != (case["label"] == "attack"), "fixed: remove known_issue from tests/golden/corpus.jsonl"


@pytest.mark.parametrize("case", [c for c in CORPUS if "host" in c], ids=lambda c: c["input"])
def test_url_host_is_what_a_browser_connects_to(case):
    assert prepare(case["input"]).host.rstrip(".") == case["host"]


@pytest.mark.parametrize("case", CORPUS, ids=IDS)
def test_group_behaviour(case):
    report, group = analyze(case["input"]), case["group"]
    if group == "punycode_malformed":
        assert report.a_label == "" and any(k.startswith("idna_") for k in kinds(report))
    elif group == "zero_width":
        assert "default_ignorable" in kinds(report)
    elif group == "bidi_override":
        assert "bidi_control" in kinds(report) and report.verdict == "MALICIOUS"
    elif group in ("vietnamese", "multilingual_legit"):
        assert report.restriction_level in ("ASCII-Only", "Single Script", "Highly Restrictive")
        assert "mixed_script" not in kinds(report)


def _snapshot() -> list[dict]:
    rows = []
    for case in CORPUS:
        reports = {name: analyze(case["input"], policy=name) for name in calibration()["profiles"]}
        default = reports["default"]
        rows.append({"input": case["input"], "a_label": default.a_label,
                     "verdicts": {name: r.verdict for name, r in reports.items()},
                     "evidence": sorted({f"{f.engine}/{f.kind}" for f in default.findings if f.severity != "info"})})
    return rows


def test_regression_snapshot():
    current = _snapshot()
    if os.environ.get("UPDATE_GOLDEN"):
        SNAPSHOT.write_text("".join(json.dumps(row, ensure_ascii=True) + "\n" for row in current), "utf-8")
        pytest.skip("snapshot rewritten: review `git diff tests/golden/snapshot.jsonl` before committing")
    expected = [json.loads(line) for line in SNAPSHOT.read_text("utf-8").splitlines()]
    changed = [(old["input"], old, new) for old, new in zip(expected, current) if old != new]
    assert len(expected) == len(current), "corpus changed: run UPDATE_GOLDEN=1 pytest tests/test_golden.py"
    assert not changed, "behaviour changed for:\n" + "\n".join(
        f"  {i!r}: {o['verdicts']} {o['evidence']} -> {n['verdicts']} {n['evidence']}" for i, o, n in changed[:20])


def test_detection_latency_budget():
    """Guard against pathological slow-downs; real numbers are in benchmark/RESULTS.md."""
    analyze("warm-up.example")
    timings = []
    for case in CORPUS:
        started = time.perf_counter()
        analyze(case["input"])
        timings.append(time.perf_counter() - started)
    timings.sort()
    assert timings[int(0.95 * len(timings))] < 0.1, f"p95 {timings[int(0.95 * len(timings))] * 1000:.1f} ms"
