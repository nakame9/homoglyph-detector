import hashlib
import json
from pathlib import Path

import pytest

from homoglyph_detector import analyze
from homoglyph_detector.analyzer import run_engines
from homoglyph_detector.context import prepare
from homoglyph_detector.brands import load_brands
from homoglyph_detector.engines import ENGINES, EngineResult
from homoglyph_detector.scoring import calibration, probability, verdict

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ["p\u0430ypal.com", "5hopee.vn", "paypal-login.com", "xn--a.com", "paypal.com", "G\u043e\u043egle support"]


@pytest.mark.parametrize("raw", SAMPLES)
def test_engines_are_independent(raw):
    """Each engine alone gives the same result as inside the pipeline, and only tags its own findings."""
    ctx, brands = prepare(raw), load_brands()
    _, together = run_engines(raw)
    for name, engine in ENGINES.items():
        alone = engine(ctx, brands)
        assert isinstance(alone, EngineResult) and 0 <= alone.score <= 1
        assert alone.score == together[name].score
        assert {f.engine for f in alone.findings} <= {name}


def test_report_is_more_than_true_false():
    report = analyze("p\u0430ypal.com")
    assert set(report.engine_scores) == set(ENGINES)
    assert 0 <= report.probability <= 1 and report.risk_score == round(100 * report.probability)
    assert report.verdict == verdict(report.probability) == "MALICIOUS"
    assert {f.engine for f in report.findings} >= {"unicode", "brand"}


def test_repeated_evidence_counts_once():
    result = EngineResult("x")
    for _ in range(3):
        result.add("same_kind", "medium", "")
    assert result.noisy_or().score == 0.5


def test_more_evidence_never_lowers_the_risk():
    weights = calibration()["weights"]
    assert set(weights) == set(ENGINES) and all(w >= 0 for w in weights.values())
    nothing = {name: 0.0 for name in ENGINES}
    for name in ENGINES:
        assert probability({**nothing, name: 1.0}) >= probability(nothing)


def test_calibration_was_fitted_on_the_committed_benchmark():
    model = calibration()
    dataset = ROOT / model["dataset"]["file"]
    assert hashlib.sha256(dataset.read_bytes()).hexdigest() == model["dataset"]["sha256"], (
        "benchmark/dataset.jsonl changed: run python benchmark/calibrate.py")
    rows = dataset.read_text("ascii").splitlines()
    assert len(rows) == model["dataset"]["rows"] and all(json.loads(row)["label"] in (0, 1) for row in rows[:50])


def test_calibrated_quality_does_not_regress():
    metrics = calibration()["test_metrics"]
    assert metrics["roc_auc"] >= 0.9
    assert metrics["at_malicious"]["precision"] >= 0.98
    assert metrics["at_suspicious"]["f1"] >= 0.85
    assert metrics["ece"] <= 0.1
