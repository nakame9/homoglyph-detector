"""Fusion and risk policy.

Fusion: logistic regression over the engine scores -> calibrated probability. Weights and bias
are fitted by benchmark/calibrate.py on benchmark/dataset.jsonl and stored in data/calibration.json.

Risk policy: the probability -> verdict cut-offs depend on the environment. A profile names two
thresholds (SUSPICIOUS, MALICIOUS). Built-in profiles are chosen by calibrate.py from targets
on the false positive rate, measured on the benchmark's train split; a custom policy states its
own alert budget (max false positive rate) and gets thresholds from the stored operating curve.
False positive rate and recall do not depend on how many attacks the traffic contains;
precision does, so policies are stated in false positive rate, not precision.
"""
from __future__ import annotations

import json
import math
import os
from functools import cache

from .integrity import read_verified

LEVELS = ("SAFE", "SUSPICIOUS", "MALICIOUS")


@cache
def calibration() -> dict:
    return json.loads(read_verified("calibration.json"))


def probability(scores: dict[str, float]) -> float:
    """Calibrated probability that the input is a look-alike attack."""
    model = calibration()
    z = model["bias"] + sum(weight * scores[name] for name, weight in model["weights"].items())
    return 1 / (1 + math.exp(-z))


def operating_curve(labels: list[int], probs: list[float]) -> list[dict]:
    """Recall and false positive rate for every threshold between two distinct probabilities.

    A threshold t flags p >= t; it sits halfway between neighbouring scores so that a new input
    scoring a hair below a benchmark value is not flagged by rounding luck.
    """
    values = sorted({round(p, 6) for p in probs})
    cuts = [0.0] + [(a + b) / 2 for a, b in zip(values, values[1:])] + [1.0]
    positives = sum(labels)
    negatives = len(labels) - positives
    curve = []
    for t in cuts:
        flagged = [y for y, p in zip(labels, probs) if p >= t]
        curve.append({"threshold": round(t, 6), "recall": round(sum(flagged) / positives, 6),
                      "fpr": round((len(flagged) - sum(flagged)) / negatives, 6)})
    return curve


def threshold_for_fpr(max_fpr: float, curve: list[dict] | None = None) -> float:
    """Highest-recall threshold whose false positive rate stays within `max_fpr` (ties: the stricter one)."""
    if not 0 <= max_fpr <= 1:
        raise ValueError(f"false positive rate must be between 0 and 1, got {max_fpr}")
    points = [pt for pt in (curve or calibration()["operating_curve"]) if pt["fpr"] <= max_fpr]
    return max(points, key=lambda pt: (pt["recall"], pt["threshold"]))["threshold"]   # t=1.0 always qualifies


def profile(name: str | None = None) -> dict:
    """A built-in risk profile; None means $HOMOGLYPH_PROFILE or 'default'."""
    name = name or os.environ.get("HOMOGLYPH_PROFILE") or "default"
    profiles = calibration()["profiles"]
    if name not in profiles:
        raise ValueError(f"unknown risk profile '{name}'; available: {', '.join(profiles)}")
    return {"name": name, **profiles[name]}


def custom_profile(max_fpr_suspicious: float, max_fpr_malicious: float) -> dict:
    """A policy from your own alert budget: the false positive rates you accept for each verdict."""
    if max_fpr_malicious > max_fpr_suspicious:
        raise ValueError("the MALICIOUS false positive budget must not exceed the SUSPICIOUS one")
    return {"name": f"custom (max FPR {max_fpr_suspicious:g} / {max_fpr_malicious:g})",
            "suspicious": threshold_for_fpr(max_fpr_suspicious),
            "malicious": threshold_for_fpr(max_fpr_malicious)}


def at_base_rate(p: float, base_rate: float) -> float:
    """Re-express a benchmark-calibrated probability for an environment where `base_rate` of the
    inputs are attacks (Bayes prior-shift correction: odds x new prior odds / training prior odds).

    The fusion learned on a benchmark with about one attack per three inputs; a mail gateway may see
    one per thousand. The ranking and the false positive rate of a threshold do not change, but the
    chance that a flagged input is really an attack does. Valid only if the engines' evidence behaves
    on your traffic as on the benchmark (see benchmark/REAL_WORLD.md).
    """
    if not 0 < base_rate < 1:
        raise ValueError(f"base rate must be strictly between 0 and 1, got {base_rate}")
    prior = calibration()["dataset"]["train_prior"]
    if p in (0.0, 1.0):
        return p
    odds = p / (1 - p) * (base_rate / (1 - base_rate)) / (prior / (1 - prior))
    return odds / (1 + odds)


def verdict(p: float, policy: dict | None = None) -> str:
    policy = policy or profile()
    return "MALICIOUS" if p >= policy["malicious"] else "SUSPICIOUS" if p >= policy["suspicious"] else "SAFE"
