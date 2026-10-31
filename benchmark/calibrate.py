#!/usr/bin/env python3
"""Fit the fusion layer on benchmark/dataset.jsonl; write data/calibration.json and benchmark/RESULTS.md.

    python benchmark/calibrate.py

Split: 70% train / 30% test by group (sha256 of the original domain), so the permutations of
one domain are never on both sides. Model: logistic regression on the engine scores, fitted by
Newton's method with L2, weights constrained >= 0 so more evidence never lowers the risk.
Metrics are computed on the test split only.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import subprocess
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from homoglyph_detector.analyzer import run_engines  # noqa: E402
from homoglyph_detector.brands import bundled  # noqa: E402
from homoglyph_detector.cli import visible  # noqa: E402
from homoglyph_detector.engines import ENGINES  # noqa: E402

DATASET = ROOT / "benchmark" / "dataset.jsonl"
CALIBRATION = ROOT / "src" / "homoglyph_detector" / "data" / "calibration.json"
RESULTS = ROOT / "benchmark" / "RESULTS.md"
THRESHOLDS = {"suspicious": 0.5, "malicious": 0.9}   # "more likely than not" / "9 in 10"
L2 = 1.0
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def sigmoid(z: float) -> float:
    return 1 / (1 + math.exp(-z)) if z > -700 else 0.0


def solve(a: list[list[float]], b: list[float]) -> list[float]:
    n = len(b)
    m = [row[:] + [b[i]] for i, row in enumerate(a)]
    for col in range(n):
        pivot = max(range(col, n), key=lambda r: abs(m[r][col]))
        m[col], m[pivot] = m[pivot], m[col]
        for r in range(n):
            if r != col:
                factor = m[r][col] / m[col][col]
                m[r] = [x - factor * y for x, y in zip(m[r], m[col])]
    return [m[i][n] / m[i][i] for i in range(n)]


def fit(x: list[list[float]], y: list[int]) -> list[float]:
    """Logistic regression, column 0 = intercept; active-set Newton keeps the other weights >= 0."""
    active = list(range(len(x[0])))
    while True:
        w = [0.0] * len(x[0])
        for _ in range(30):
            grad = [0.0] * len(active)
            hess = [[0.0] * len(active) for _ in active]
            for xi, yi in zip(x, y):
                p = sigmoid(sum(w[j] * xi[j] for j in active))
                r = p * (1 - p)
                for a, ja in enumerate(active):
                    grad[a] += (p - yi) * xi[ja]
                    for b, jb in enumerate(active):
                        hess[a][b] += r * xi[ja] * xi[jb]
            for a, ja in enumerate(active):
                if ja:   # no penalty on the intercept
                    grad[a] += L2 * w[ja]
                    hess[a][a] += L2
            step = solve(hess, grad)
            for a, ja in enumerate(active):
                w[ja] -= step[a]
            if max(abs(s) for s in step) < 1e-8:
                break
        negative = [j for j in active if j and w[j] < 0]
        if not negative:
            return w
        active.remove(min(negative, key=lambda j: w[j]))


def roc_auc(y: list[int], p: list[float]) -> float:
    order = sorted(range(len(p)), key=lambda i: p[i])
    ranks = [0.0] * len(p)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and p[order[j + 1]] == p[order[i]]:
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2 + 1
        i = j + 1
    positives = sum(y)
    negatives = len(y) - positives
    return (sum(r for r, yi in zip(ranks, y) if yi) - positives * (positives + 1) / 2) / (positives * negatives)


def confusion(y: list[int], flagged: list[bool]) -> dict:
    tp = sum(1 for yi, f in zip(y, flagged) if yi and f)
    fp = sum(1 for yi, f in zip(y, flagged) if not yi and f)
    fn = sum(1 for yi, f in zip(y, flagged) if yi and not f)
    negatives = len(y) - sum(y)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
            "false_positive_rate": round(fp / negatives, 4), "false_positives": fp, "false_negatives": fn}


def reliability(y: list[int], p: list[float], bins: int = 10) -> tuple[list[tuple], float]:
    table, ece = [], 0.0
    for b in range(bins):
        idx = [i for i, pi in enumerate(p) if b / bins <= pi < (b + 1) / bins or (b == bins - 1 and pi == 1.0)]
        if idx:
            predicted = sum(p[i] for i in idx) / len(idx)
            observed = sum(y[i] for i in idx) / len(idx)
            table.append((f"{b / bins:.1f}-{(b + 1) / bins:.1f}", len(idx), predicted, observed))
            ece += abs(predicted - observed) * len(idx) / len(p)
    return table, ece


def main() -> int:
    os.environ.pop("HOMOGLYPH_BRANDS", None)   # calibrate on the bundled brand database only
    raw = DATASET.read_bytes()
    rows = [json.loads(line) for line in raw.decode("ascii").splitlines()]
    names = list(ENGINES)
    for row in rows:
        _, results = run_engines(row["domain"])
        row["scores"] = [results[n].score for n in names]
        row["severity"] = max((SEVERITY_RANK[f.severity] for r in results.values() for f in r.findings), default=0)
        row["test"] = int(hashlib.sha256(row["group"].encode()).hexdigest(), 16) % 10 >= 7
    train = [r for r in rows if not r["test"]]
    test = [r for r in rows if r["test"]]

    w = fit([[1.0, *r["scores"]] for r in train], [r["label"] for r in train])
    for r in rows:
        r["p"] = sigmoid(w[0] + sum(wi * s for wi, s in zip(w[1:], r["scores"])))

    y = [r["label"] for r in test]
    p = [r["p"] for r in test]
    table, ece = reliability(y, p)
    metrics = {
        "roc_auc": round(roc_auc(y, p), 4),
        "brier": round(sum((pi - yi) ** 2 for pi, yi in zip(p, y)) / len(y), 4),
        "ece": round(ece, 4),
        "at_suspicious": confusion(y, [pi >= THRESHOLDS["suspicious"] for pi in p]),
        "at_malicious": confusion(y, [pi >= THRESHOLDS["malicious"] for pi in p]),
    }
    baseline = {   # verdict from the worst finding severity, no calibration
        "suspicious_or_worse": confusion(y, [r["severity"] >= 2 for r in test]),
        "malicious": confusion(y, [r["severity"] >= 3 for r in test]),
    }
    model = {
        "weights": {n: round(wi, 4) for n, wi in zip(names, w[1:])},
        "bias": round(w[0], 4),
        "thresholds": THRESHOLDS,
        "brands": {k: v for k, v in bundled().info().items() if k in ("name", "version", "sha256")},
        "dataset": {"file": "benchmark/dataset.jsonl", "sha256": hashlib.sha256(raw).hexdigest(),
                    "rows": len(rows), "attacks": sum(r["label"] for r in rows),
                    "train_rows": len(train), "test_rows": len(test)},
        "test_metrics": metrics,
        "baseline_test_metrics": baseline,
    }
    CALIBRATION.write_text(json.dumps(model, indent=2) + "\n", encoding="utf-8")

    by_category = defaultdict(list)
    for r in test:
        by_category[r["category"]].append(r)
    errors_fp = sorted((r for r in test if not r["label"] and r["p"] >= THRESHOLDS["suspicious"]), key=lambda r: -r["p"])
    errors_fn = sorted((r for r in test if r["label"] and r["p"] < THRESHOLDS["suspicious"]), key=lambda r: r["p"])

    def show(d: str) -> str:
        return visible(d).replace("|", "\\|")

    lines = [
        "# Benchmark results", "",
        f"Generated by `benchmark/calibrate.py` on {date.today().isoformat()}. Dataset: `benchmark/dataset.jsonl` "
        f"({len(rows)} rows, {model['dataset']['attacks']} attacks), built by `benchmark/build_dataset.py`.",
        f"Train {len(train)} / test {len(test)} rows, split by original domain. **All numbers are on the test split.**", "",
        "## Fusion model", "",
        "| engine | weight |", "|---|---|",
        *[f"| {n} | {wi} |" for n, wi in model["weights"].items()],
        f"| *bias* | {model['bias']} |", "",
        "## Calibrated model vs. plain severity rules", "",
        "| | precision | recall | F1 | false positive rate |", "|---|---|---|---|---|",
        *[f"| {label} | {m['precision']} | {m['recall']} | {m['f1']} | {m['false_positive_rate']} |" for label, m in [
            (f"calibrated, p >= {THRESHOLDS['suspicious']} (SUSPICIOUS+)", metrics["at_suspicious"]),
            (f"calibrated, p >= {THRESHOLDS['malicious']} (MALICIOUS)", metrics["at_malicious"]),
            ("severity rules, no calibration: SUSPICIOUS+", baseline["suspicious_or_worse"]),
            ("severity rules, no calibration: MALICIOUS", baseline["malicious"])]],
        "", f"ROC-AUC **{metrics['roc_auc']}**, Brier score {metrics['brier']}, "
            f"expected calibration error (ECE) {metrics['ece']}.", "",
        "## Calibration (reliability)", "",
        "Predicted probability vs. the share of real attacks in each bin.", "",
        "| predicted | rows | mean predicted | observed attack rate |", "|---|---|---|---|",
        *[f"| {b} | {n} | {pr:.3f} | {ob:.3f} |" for b, n, pr, ob in table], "",
        "## Detection by category", "",
        f"Share flagged SUSPICIOUS or worse (p >= {THRESHOLDS['suspicious']}). For attacks this is recall; for benign rows it is the false positive rate.", "",
        "| category | label | rows | flagged |", "|---|---|---|---|",
        *[f"| {c} | {'attack' if rs[0]['label'] else 'benign'} | {len(rs)} | "
          f"{sum(r['p'] >= THRESHOLDS['suspicious'] for r in rs) / len(rs):.1%} |" for c, rs in sorted(by_category.items())],
        "", "## Hardest errors", "",
        "False positives (benign, flagged):", "",
        *[f"- `{show(r['domain'])}` p={r['p']:.2f} ({r['category']})" for r in errors_fp[:15]], "",
        "False negatives (attacks, missed):", "",
        *[f"- `{show(r['domain'])}` p={r['p']:.2f} ({r['category']})" for r in errors_fn[:15]], "",
        "## Caveats", "",
        "- Probabilities are calibrated to this dataset's mix (about one attack per two benign rows). "
        "Real traffic has far fewer attacks, so treat the score as a ranking and the thresholds as review cut-offs.",
        "- Attacks come from dnstwist and a small curated list; benign rows from the OpenDNS top 10,000, "
        "which may itself contain a few look-alikes.",
        "- ASCII typos of brands that are not in `brands.json` are out of scope (nothing to compare with).", "",
    ]
    RESULTS.write_text("\n".join(lines), encoding="utf-8")
    subprocess.run([sys.executable, str(ROOT / "scripts" / "seal_data.py")], check=True, stdout=subprocess.DEVNULL)
    print(json.dumps({"weights": model["weights"], "bias": model["bias"], **metrics}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
