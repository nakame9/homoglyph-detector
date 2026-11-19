import hashlib
import importlib.util
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("labeled_baseline", ROOT / "benchmark" / "labeled_baseline.py")
baseline = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = baseline
SPEC.loader.exec_module(baseline)


def run_baseline(input_path, output, coverage=0):
    return subprocess.run([
        sys.executable, str(ROOT / "benchmark" / "real_world.py"), "prepare-baseline", str(input_path),
        "--output", str(output), "--source", "synthetic pilot v1; generated locally",
        "--validation-start", "2026-02-01", "--holdout-start", "2026-03-01",
        "--per-group", "1", "--coverage", str(coverage),
    ], capture_output=True, text=True, encoding="utf-8")


def test_offline_baseline_is_private_reproducible_and_split_by_registered_domain(tmp_path):
    rows = [
        {"url": "https://apple.com/", "label": "benign", "observed_on": "2026-03-12"},
        {"url": "https://paypal.com%2FUSER_SECRET:PASSWORD_SECRET@apple.com/private?q=QUERY_SECRET#FRAGMENT_SECRET",
         "label": "userinfo", "observed_on": "2026-02-01", "userinfo_lure": "paypal.com"},
        {"url": "https://pa\u0443pal.com/", "label": "homoglyph", "observed_on": "2026-01-04"},
        {"url": "https://pa\u0443pal.com/EXTRA_SECRET", "label": "homoglyph", "observed_on": "2026-01-04"},
        {"url": "https://paypa1.example.org:PORT_SECRET/", "label": "typosquat", "observed_on": "2026-03-01"},
        {"url": "https://paypal-login.github.io/", "label": "combosquat", "observed_on": "2026-03-04"},
        {"url": "https://example.com/", "label": "benign", "observed_on": "2026-03-08"},
        {"url": "https://127.0.0.1/", "label": "other_phish", "observed_on": "2026-01-12"},
    ]
    files = []
    for index, order in enumerate((rows, reversed(rows))):
        source = tmp_path / f"input-{index}.jsonl"
        source.write_text("\n".join(map(json.dumps, order)), encoding="utf-8")
        output = tmp_path / f"result-{index}"
        result = run_baseline(source, output)
        assert result.returncode == 0, result.stderr
        manifest = json.loads(result.stdout)
        assert manifest == json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["input_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
        assert "publicsuffixlist" in manifest["runtime"]
        contents = {}
        by_split = {}
        for name, metadata in manifest["files"].items():
            data = (output / name).read_bytes()
            assert hashlib.sha256(data).hexdigest() == metadata["sha256"]
            assert b"_SECRET" not in data
            contents[name] = data
            by_split[name] = [json.loads(line) for line in data.splitlines()]
        assert all(manifest["strata"][group]["selected"] == 1 for group in baseline.STRATA)
        assert manifest["counts"]["without_registered_domain"] == 1
        assert manifest["counts"]["conflicting_label_domains"] == 1
        assert [r["domain"] for r in by_split["validation.jsonl"]] == ["apple.com"]
        assert by_split["validation.jsonl"][0]["url"] == "https://paypal.com@apple.com"
        assert next(r for r in by_split["holdout.jsonl"] if r["domain"] == "example.org")["url"].endswith(":invalid")
        assert {r["domain"] for r in by_split["holdout.jsonl"]} == {
            "example.org", "paypal-login.github.io", "example.com"}
        assert len({r["domain"] for group in by_split.values() for r in group}) == 5
        files.append(contents)
    assert files[0] == files[1]


def test_coverage_is_reserved_before_stratification_without_running_engines(monkeypatch):
    import homoglyph_detector
    monkeypatch.setattr(homoglyph_detector, "analyze", lambda *args: pytest.fail("labels must not use verdicts"))
    rows = [{"url": f"https://{label}-{i}.com/", "label": label, "observed_on": "2026-01-01",
             **({"url": f"https://paypal.com@userinfo-{i}.com/", "userinfo_lure": "paypal.com"}
                if label == "userinfo" else {})} for label in baseline.STRATA for i in range(2)]
    output, report = baseline.prepare_corpus(map(json.dumps, rows), date(2026, 2, 1), date(2026, 3, 1), 1, 1, 2026)
    records = [r for group in output.values() for r in group]
    assert len(records) == len({r["domain"] for r in records}) == 5
    assert sum(r["cohort"] == "coverage" for r in records) == 1
    assert all(report["strata"][label]["shortfall"] == 0 for label in baseline.STRATA)


@pytest.mark.parametrize("row", [
    {"url": "https://USER_SECRET@example.org/?q=QUERY_SECRET", "label": "bad", "observed_on": "2026-01-01"},
    {"url": "https://USER_SECRET@example.org/", "label": "userinfo", "observed_on": "2026-01-01"},
    {"url": "https://USER_SECRET@example.org/", "label": "benign", "observed_on": "bad"},
])
def test_invalid_labels_are_refused_without_leaking_input_or_writing_output(tmp_path, row):
    source = tmp_path / "input.jsonl"
    source.write_text(json.dumps(row), encoding="utf-8")
    output = tmp_path / "result"
    result = run_baseline(source, output)
    assert result.returncode == 1 and "line 1" in result.stderr
    assert "_SECRET" not in result.stderr and result.stdout == "" and not output.exists()


def test_written_host_evidence_is_preserved_and_existing_output_is_not_overwritten(tmp_path):
    raw = "https://pa\u200bypal.com/PRIVATE_SECRET?q=QUERY_SECRET"
    sample = baseline.sample_from_row({"url": raw, "label": "homoglyph", "observed_on": "2026-01-01"})
    assert sample.domain == "paypal.com" and sample.url == "https://pa\u200bypal.com"
    assert sample.source_length == len(raw)
    source = tmp_path / "input.jsonl"
    source.write_text("", encoding="utf-8")
    output = tmp_path / "result"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_text("keep", encoding="utf-8")
    assert run_baseline(source, output).returncode == 1
    assert marker.read_text(encoding="utf-8") == "keep"
