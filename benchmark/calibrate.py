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
from homoglyph_detector.scoring import operating_curve, threshold_for_fpr  # noqa: E402

DATASET = ROOT / "benchmark" / "dataset.jsonl"
CALIBRATION = ROOT / "src" / "homoglyph_detector" / "data" / "calibration.json"
RESULTS = ROOT / "benchmark" / "RESULTS.md"
THRESHOLDS = {"suspicious": 0.5, "malicious": 0.9}   # default profile: "more likely than not" / "9 in 10"
LEVELS = ("suspicious", "malicious")
# Risk profiles: each threshold is a target, resolved on the train split, measured on the test split.
# Targets are false positive rates (alert budgets): unlike precision they do not depend on how
# many attacks a given environment sees.
PROFILES = {
    "default": {"description": "General use: SUSPICIOUS when more likely than not, MALICIOUS at 9 in 10.",
                "suspicious": {"probability": THRESHOLDS["suspicious"]},
                "malicious": {"probability": THRESHOLDS["malicious"]}},
    "banking": {"description": "High-value transactions (banking, payments): flag and block on any evidence; "
                               "false positives go to step-up verification.",
                "suspicious": {"max_fpr": 0.05}, "malicious": {"max_fpr": 0.02}},
    "browser": {"description": "End-user browser warnings: every alert interrupts a person, "
                               "so only strong look-alike evidence counts.",
                "suspicious": {"max_fpr": 0.002}, "malicious": {"max_fpr": 0.0005}},
}
FPR_GRID = (0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05)
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


def operating(y: list[int], p: list[float], threshold: float) -> dict:
    m = confusion(y, [pi >= threshold for pi in p])
    return {"recall": m["recall"], "false_positive_rate": m["false_positive_rate"],
            "false_alerts_per_10k": round(m["false_positive_rate"] * 10_000, 1), "precision": m["precision"]}


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
    curve = operating_curve([r["label"] for r in train], [r["p"] for r in train])
    profiles = {}
    for name, spec in PROFILES.items():
        cut = {level: spec[level]["probability"] if "probability" in spec[level]
               else threshold_for_fpr(spec[level]["max_fpr"], curve) for level in LEVELS}
        cut["malicious"] = max(cut["malicious"], cut["suspicious"])
        profiles[name] = {"description": spec["description"], **cut,
                          "targets": {level: spec[level] for level in LEVELS},
                          "test": {level: operating(y, p, cut[level]) for level in LEVELS}}
    grid = {}
    for max_fpr in FPR_GRID:
        t = threshold_for_fpr(max_fpr, curve)
        grid.setdefault(t, {"max_fpr_target": max_fpr, "threshold": t, **operating(y, p, t)})

    model = {
        "weights": {n: round(wi, 4) for n, wi in zip(names, w[1:])},
        "bias": round(w[0], 4),
        "profiles": profiles,
        "brands": {k: v for k, v in bundled().info().items() if k in ("name", "version", "sha256")},
        "dataset": {"file": "benchmark/dataset.jsonl", "sha256": hashlib.sha256(raw).hexdigest(),
                    "rows": len(rows), "attacks": sum(r["label"] for r in rows),
                    "train_rows": len(train), "test_rows": len(test)},
        "test_metrics": metrics,
        "operating_points": list(grid.values()),   # test-split rates for common alert budgets
        "operating_curve": curve,                  # train split: used by --max-fpr
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
        "# Kết quả benchmark", "",
        f"Sinh tự động bởi `benchmark/calibrate.py` ngày {date.today().isoformat()}. Bộ dữ liệu: `benchmark/dataset.jsonl` "
        f"({len(rows)} dòng, {model['dataset']['attacks']} tấn công), tạo bởi `benchmark/build_dataset.py`.",
        f"Train {len(train)} / test {len(test)} dòng, tách theo domain gốc. **Mọi con số đều đo trên tập test.**", "",
        "## Mô hình hợp nhất (fusion)", "",
        "| engine | trọng số |", "|---|---|",
        *[f"| {n} | {wi} |" for n, wi in model["weights"].items()],
        f"| *bias* | {model['bias']} |", "",
        "## Mô hình đã hiệu chỉnh so với luật mức độ nghiêm trọng", "",
        "| | precision | recall | F1 | tỷ lệ báo nhầm |", "|---|---|---|---|---|",
        *[f"| {label} | {m['precision']} | {m['recall']} | {m['f1']} | {m['false_positive_rate']} |" for label, m in [
            (f"đã hiệu chỉnh, p >= {THRESHOLDS['suspicious']} (SUSPICIOUS trở lên)", metrics["at_suspicious"]),
            (f"đã hiệu chỉnh, p >= {THRESHOLDS['malicious']} (MALICIOUS)", metrics["at_malicious"]),
            ("luật mức độ, không hiệu chỉnh: SUSPICIOUS trở lên", baseline["suspicious_or_worse"]),
            ("luật mức độ, không hiệu chỉnh: MALICIOUS", baseline["malicious"])]],
        "", f"ROC-AUC **{metrics['roc_auc']}**, Brier score {metrics['brier']}, "
            f"sai số hiệu chỉnh kỳ vọng (ECE) {metrics['ece']}.", "",
        "## Hồ sơ rủi ro (risk profiles)", "",
        "Ngưỡng chọn trên tập train theo mục tiêu tỷ lệ báo nhầm, đo lại trên tập test. "
        "Báo nhầm / 10k = số cảnh báo sai trên 10.000 domain hợp lệ, không phụ thuộc tỷ lệ tấn công của môi trường.", "",
        "| profile | ngưỡng SUSPICIOUS | recall | báo nhầm / 10k | ngưỡng MALICIOUS | recall | báo nhầm / 10k |",
        "|---|---|---|---|---|---|---|",
        *[f"| {n} | {pr['suspicious']:.4f} | {pr['test']['suspicious']['recall']} | "
          f"{pr['test']['suspicious']['false_alerts_per_10k']} | {pr['malicious']:.4f} | "
          f"{pr['test']['malicious']['recall']} | {pr['test']['malicious']['false_alerts_per_10k']} |"
          for n, pr in profiles.items()], "",
        "## Các điểm vận hành", "",
        "Muốn tự đặt ngân sách báo nhầm: chọn một dòng (`--max-fpr`). Các mục tiêu cho cùng ngưỡng được gộp.", "",
        "| mục tiêu FPR tối đa (train) | ngưỡng | recall (test) | FPR (test) | báo nhầm / 10k (test) |",
        "|---|---|---|---|---|",
        *[f"| {g['max_fpr_target']} | {g['threshold']:.4f} | {g['recall']} | {g['false_positive_rate']} | "
          f"{g['false_alerts_per_10k']} |" for g in grid.values()], "",
        "## Độ tin cậy của xác suất (reliability)", "",
        "Xác suất dự đoán so với tỷ lệ tấn công thật trong từng khoảng.", "",
        "| khoảng dự đoán | số dòng | dự đoán trung bình | tỷ lệ tấn công thực tế |", "|---|---|---|---|",
        *[f"| {b} | {n} | {pr:.3f} | {ob:.3f} |" for b, n, pr, ob in table], "",
        "## Phát hiện theo loại", "",
        f"Tỷ lệ bị gắn cờ SUSPICIOUS trở lên (p >= {THRESHOLDS['suspicious']}). Với tấn công đây là recall; với mẫu hợp lệ đây là tỷ lệ báo nhầm.", "",
        "| loại | nhãn | số dòng | bị gắn cờ |", "|---|---|---|---|",
        *[f"| {c} | {'tấn công' if rs[0]['label'] else 'hợp lệ'} | {len(rs)} | "
          f"{sum(r['p'] >= THRESHOLDS['suspicious'] for r in rs) / len(rs):.1%} |" for c, rs in sorted(by_category.items())],
        "", "## Các lỗi khó nhất", "",
        "Báo nhầm (hợp lệ nhưng bị gắn cờ):", "",
        *[f"- `{show(r['domain'])}` p={r['p']:.2f} ({r['category']})" for r in errors_fp[:15]], "",
        "Bỏ lọt (tấn công nhưng không bị gắn cờ):", "",
        *[f"- `{show(r['domain'])}` p={r['p']:.2f} ({r['category']})" for r in errors_fn[:15]], "",
        "## Lưu ý", "",
        "- Xác suất được hiệu chỉnh theo tỷ lệ của bộ dữ liệu này (khoảng 1 tấn công trên 2 mẫu hợp lệ). "
        "Lưu lượng thật có ít tấn công hơn nhiều: hãy dùng điểm như thứ hạng và ngưỡng như mốc để xem xét.",
        "- Tấn công lấy từ dnstwist và một danh sách tuyển chọn nhỏ; mẫu hợp lệ lấy từ OpenDNS top 10.000, "
        "bản thân danh sách này có thể lẫn vài domain giả mạo.",
        "- Lỗi gõ ASCII của thương hiệu không có trong `brands.json` nằm ngoài phạm vi (không có gì để so sánh).", "",
    ]
    RESULTS.write_text("\n".join(lines), encoding="utf-8")
    subprocess.run([sys.executable, str(ROOT / "scripts" / "seal_data.py")], check=True, stdout=subprocess.DEVNULL)
    print(json.dumps({"weights": model["weights"], "bias": model["bias"], **metrics}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
