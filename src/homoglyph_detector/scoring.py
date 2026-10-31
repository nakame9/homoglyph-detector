"""Fusion layer: logistic regression over the engine scores.

Weights, bias and thresholds are not hand-tuned: benchmark/calibrate.py fits them on
benchmark/dataset.jsonl and writes data/calibration.json (with the test-split metrics).
"""
from __future__ import annotations

import json
import math
from functools import cache

from .unicode_data import DATA


@cache
def calibration() -> dict:
    return json.loads((DATA / "calibration.json").read_text("utf-8"))


def probability(scores: dict[str, float]) -> float:
    """Calibrated probability that the input is a look-alike attack."""
    model = calibration()
    z = model["bias"] + sum(weight * scores[name] for name, weight in model["weights"].items())
    return 1 / (1 + math.exp(-z))


def verdict(p: float) -> str:
    thresholds = calibration()["thresholds"]
    return "MALICIOUS" if p >= thresholds["malicious"] else "SUSPICIOUS" if p >= thresholds["suspicious"] else "SAFE"
