#!/usr/bin/env python3
"""Real-world evaluation: real phishing, international benign domains, time, adversarial variants, calibration.

    python benchmark/real_world.py            # needs network on first run; ~10 minutes on 2 cores

Writes benchmark/REAL_WORLD.md, benchmark/adversarial.jsonl and docs/img/reliability.svg.

Data (downloaded into benchmark/.cache/, never committed):
  phishing  OpenPhish Community Feed, git history of github.com/openphish/public_feed pinned at
            OPENPHISH_COMMIT: every URL with the time it first appeared (non-commercial use only,
            https://openphish.com/terms.html; only hostnames are kept)
  benign    Chrome UX Report top 1M origins (github.com/zakird/crux-top-lists pinned at CRUX_COMMIT):
            the real distribution of popular sites across countries, scripts and IDNs

Experiments:
  1. detection on real phishing, overall and inside the tool's scope (look-alikes of protected brands)
  2. false positives on international / multilingual benign domains, by region and for IDNs
  3. temporal validation: fusion fitted on phishing seen before CUTOFF, tested on phishing after it
  4. adversarial: leave-one-technique-out on the synthetic benchmark, and NOVEL_TECHNIQUES never used
     anywhere in development
  5. calibration: Brier score, ECE, reliability diagram, and the base-rate correction
"""
from __future__ import annotations

import gzip
import hashlib
import json
import random
import re
import subprocess
import sys
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from multiprocessing import Pool
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "benchmark"))
from calibrate import fit, reliability, roc_auc, sigmoid  # noqa: E402

from homoglyph_detector.analyzer import run_engines  # noqa: E402
from homoglyph_detector.brands import load_brands  # noqa: E402
from homoglyph_detector.engines import ENGINES  # noqa: E402
from homoglyph_detector.scoring import at_base_rate, calibration, profile  # noqa: E402

CACHE = ROOT / "benchmark" / ".cache"
OUT = ROOT / "benchmark" / "REAL_WORLD.md"
ADVERSARIAL = ROOT / "benchmark" / "adversarial.jsonl"
FIGURE = ROOT / "docs" / "img" / "reliability.svg"
OPENPHISH_REPO, OPENPHISH_COMMIT = "https://github.com/openphish/public_feed", "cd3df159544e349cb8cf070f595d5d7509b3d284"
CRUX_COMMIT = "35ba243941defcd21882b134d9dd354824922482"
CRUX_URL = f"https://raw.githubusercontent.com/zakird/crux-top-lists/{CRUX_COMMIT}/data/global/current.csv.gz"
CUTOFF = datetime(2026, 5, 1, tzinfo=timezone.utc)
SEED = 2026
PHISH_SAMPLE = 30_000     # uniform sample of all phishing hosts, for overall rates
BENIGN_SAMPLE = 40_000    # uniform sample of the CrUX top 1M, plus every IDN in it
NAMES = list(ENGINES)
REGIONS = {
    "Việt Nam": {"vn"}, "Đông Á": {"jp", "cn", "kr", "tw", "hk"},
    "Nga, Đông Âu (Cyrillic)": {"ru", "ua", "by", "kz", "bg", "rs", "su"},
    "Châu Âu": {"de", "fr", "it", "es", "pl", "nl", "cz", "ro", "hu", "gr", "pt", "se", "at", "ch", "be", "dk",
                "fi", "no", "sk", "uk", "eu", "ie", "lt", "lv", "ee", "hr", "si"},
    "Mỹ Latinh": {"br", "ar", "mx", "cl", "co", "pe", "ve", "ec", "uy"},
    "Nam Á, Trung Đông, ĐNÁ khác": {"in", "id", "ir", "tr", "th", "pk", "bd", "my", "ph", "sa", "ae", "il", "eg"},
}


# --- data -------------------------------------------------------------------------

def phishing_hosts() -> dict[str, int]:
    """Every phishing hostname in the OpenPhish feed history with the first time it appeared."""
    repo = CACHE / "openphish.git"
    if not repo.exists():
        subprocess.run(["git", "clone", "-q", "--bare", OPENPHISH_REPO, str(repo)], check=True)
    log = subprocess.run(["git", "-C", str(repo), "log", "--reverse", "--format=@@%ct", "-p", "-U0",
                          OPENPHISH_COMMIT, "--", "feed.txt"], check=True, capture_output=True).stdout
    first, ts = {}, 0
    for line in log.decode("utf-8", "replace").splitlines():
        if line.startswith("@@") and line[2:].isdigit():
            ts = int(line[2:])
        elif line.startswith("+") and not line.startswith("+++"):
            try:
                host = (urlsplit(line[1:].strip()).hostname or "").rstrip(".")
            except ValueError:
                continue
            if host and host not in first:
                first[host] = ts
    return first


def crux_hosts() -> list[str]:
    path = CACHE / "crux.csv.gz"
    if not path.exists():
        with urllib.request.urlopen(CRUX_URL, timeout=120) as response:
            path.write_bytes(response.read())
    hosts = []
    for line in gzip.decompress(path.read_bytes()).decode().splitlines()[1:]:
        host = urlsplit(line.rsplit(",", 1)[0]).hostname
        if host:
            hosts.append(host)
    return hosts


def in_scope(host: str, keywords: list[str]) -> str | None:
    """Transparent rule, independent of the engines: why a phishing host is something this tool targets."""
    if "xn--" in host or not host.isascii():
        return "idn"
    text = re.sub(r"[^a-z0-9]", "", host)
    return "brand" if any(k in text for k in keywords) else None


def region(host: str) -> str:
    tld = host.rsplit(".", 1)[-1]
    if tld.startswith("xn--"):
        return "IDN TLD"
    return next((name for name, tlds in REGIONS.items() if tld in tlds), "gTLD / khác")


def _score(host: str) -> list[float]:
    _, results = run_engines(host)
    return [results[n].score for n in NAMES]


def score_all(hosts: list[str]) -> dict[str, list[float]]:
    cache = CACHE / "scores.jsonl"
    known = {}
    if cache.exists():
        for line in cache.read_text("utf-8").splitlines():
            row = json.loads(line)
            known[row["h"]] = row["s"]
    todo = [h for h in dict.fromkeys(hosts) if h not in known]
    if todo:
        with Pool() as pool, cache.open("a", encoding="utf-8") as out:
            for host, scores in zip(todo, pool.imap(_score, todo, chunksize=200)):
                known[host] = scores
                out.write(json.dumps({"h": host, "s": scores}) + "\n")
    return known


# --- metrics ----------------------------------------------------------------------

def prob(w: list[float], scores: list[float]) -> float:
    return sigmoid(w[0] + sum(wi * s for wi, s in zip(w[1:], scores)))


def production_weights() -> list[float]:
    model = calibration()
    return [model["bias"], *(model["weights"][n] for n in NAMES)]


def pct(x: float) -> str:
    return f"{100 * x:.1f}%".replace(".", ",")


def rate(hits: int, total: int) -> str:
    return f"{pct(hits / total)} ({hits:,}/{total:,})".replace(",", ".") if total else "–"


def flagged(p: float, level: str = "suspicious", name: str = "default") -> bool:
    return p >= profile(name)[level]


def recall_at_fpr(y: list[int], p: list[float], max_fpr: float) -> tuple[float, float]:
    """Best recall whose FPR on these negatives stays within max_fpr (threshold chosen on the same data)."""
    negatives = sorted((pi for pi, yi in zip(p, y) if not yi), reverse=True)
    k = int(max_fpr * len(negatives))
    t = negatives[k] + 1e-12 if k < len(negatives) else 0.0
    positives = [pi for pi, yi in zip(p, y) if yi]
    return sum(pi >= t for pi in positives) / len(positives), t


def brier(y: list[int], p: list[float]) -> float:
    return sum((pi - yi) ** 2 for pi, yi in zip(p, y)) / len(y)


# --- adversarial ------------------------------------------------------------------

LATIN_EXT = {"a": "ɑ", "i": "ı", "g": "ɡ", "o": "ᴏ", "c": "ᴄ", "s": "ꜱ", "u": "ᴜ"}
ARMENIAN = {"o": "օ", "u": "ս", "h": "հ", "n": "ո", "q": "զ", "g": "ց", "d": "ԁ"}
LEET = {"a": "4", "e": "3", "o": "0", "s": "5", "i": "1", "g": "9", "t": "7", "b": "8"}
MATH_BOLD = {ch: chr(0x1D41A + i) for i, ch in enumerate("abcdefghijklmnopqrstuvwxyz")}
PLATFORMS = ["vercel.app", "pages.dev", "github.io", "netlify.app", "web.app", "workers.dev", "r2.dev"]
WORDS = ["login", "secure", "verify", "support", "account", "wallet", "update", "help"]


def _swap(word: str, table: dict, rng: random.Random, k: int = 1) -> str:
    spots = [i for i, ch in enumerate(word) if ch in table]
    for i in rng.sample(spots, min(k, len(spots))):
        word = word[:i] + table[word[i]] + word[i + 1:]
    return word


NOVEL_TECHNIQUES = {
    # each: (description, generator(brand keyword, official domain, rng) -> attack or None)
    "latin_ext_homoglyph": ("chữ Latin mở rộng / IPA trông giống (ɑ, ı, ɡ, ᴏ)",
                            lambda k, d, r: _swap(k, LATIN_EXT, r) + "." + d.split(".", 1)[1]),
    "armenian_homoglyph": ("chữ Armenia trông giống (օ, ս, հ, ո)", lambda k, d, r: _swap(k, ARMENIAN, r) + ".com"),
    "uppercase_cyrillic": ("viết hoa, một chữ Cyrillic hoa", lambda k, d, r: _swap(
        k.upper(), {"A": "А", "E": "Е", "O": "О", "P": "Р", "C": "С", "K": "К"}, r)
        + ".COM"),
    "math_alphanumeric": ("chữ toán học 𝐩𝐚𝐲𝐩𝐚𝐥 (IDNA ánh xạ về ASCII)",
                          lambda k, d, r: "".join(MATH_BOLD.get(c, c) for c in k) + ".com"),
    "heavy_leet": ("thay nhiều chữ bằng số, kể cả cặp không có trong bảng (3→e, 4→a, 7→t)",
                   lambda k, d, r: _swap(k, LEET, r, 2) + ".com"),
    "leet_plus_tld_swap": ("thay chữ bằng số + đổi đuôi", lambda k, d, r: _swap(k, LEET, r) + "." + r.choice(
        ["top", "xyz", "shop", "cc", "icu", "online"])),
    "platform_subdomain": ("tên thương hiệu trên nền tảng hosting (kiểu phổ biến nhất ngoài thực tế)",
                           lambda k, d, r: f"{k}-{r.choice(WORDS)}.{r.choice(PLATFORMS)}"),
    "brand_as_subdomain": ("domain thật đặt làm subdomain của domain kẻ gian",
                           lambda k, d, r: f"{d}.{r.choice(WORDS)}-{r.randint(10, 99)}.{r.choice(['top', 'com', 'xyz'])}"),
    "split_by_dot": ("tách tên thương hiệu bằng dấu chấm", lambda k, d, r: (
        f"{k[:len(k) // 2]}.{k[len(k) // 2:]}-{r.choice(WORDS)}.com" if len(k) >= 6 else None)),
    "homoglyph_combosquat": ("homoglyph Cyrillic + từ ghép", lambda k, d, r: f"{r.choice(WORDS)}-" + _swap(
        k, {"a": "а", "o": "о", "e": "е", "p": "р", "c": "с"}, r) + ".com"),
    "double_letter_drop": ("bỏ một chữ cái đôi / thêm chữ cái đôi", lambda k, d, r: (
        re.sub(r"(.)\1", r"\1", k, count=1) if re.search(r"(.)\1", k) else re.sub(r"([aeiou])", r"\1\1", k, count=1))
        + ".net"),
}


def build_adversarial() -> list[dict]:
    rng = random.Random(SEED)
    rows = []
    for brand in load_brands():
        domain = brand["domains"][0]
        for keyword in brand["keywords"]:
            for name, (_, make) in NOVEL_TECHNIQUES.items():
                attack = make(keyword, domain, rng)
                if attack and attack.lower() != domain:
                    rows.append({"technique": name, "brand": brand["name"], "input": attack})
    ADVERSARIAL.write_text("".join(json.dumps(r, ensure_ascii=True) + "\n" for r in rows), "utf-8")
    return rows


# --- figure -----------------------------------------------------------------------

def reliability_figure(curves: dict[str, tuple[list[int], list[float]]]) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(6.4, 5.2))
    ax.plot([0, 1], [0, 1], color="#888", linestyle="--", linewidth=1, label="hiệu chỉnh hoàn hảo")
    for (label, (y, p)), color in zip(curves.items(), ["#2563eb", "#dc2626", "#16a34a", "#9333ea"]):
        table, ece = reliability(y, p)
        xs = [row[2] for row in table]
        ys = [row[3] for row in table]
        ax.plot(xs, ys, marker="o", color=color, label=f"{label} (ECE {ece:.3f})")
    ax.set_xlabel("xác suất dự đoán (trung bình mỗi khoảng)")
    ax.set_ylabel("tỷ lệ tấn công thực tế")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.grid(alpha=0.3)
    ax.legend(fontsize=8, loc="upper left")
    ax.set_title("Reliability diagram")
    FIGURE.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(FIGURE, format="svg", metadata={"Date": None})
    plt.close(fig)


# --- main -------------------------------------------------------------------------

def main() -> int:
    CACHE.mkdir(exist_ok=True)
    rng = random.Random(SEED)
    keywords = [k for b in load_brands() for k in b["keywords"]]
    w0 = production_weights()
    lines = ["# Đánh giá thực tế", "",
             "Sinh tự động bởi `benchmark/real_world.py`. Dữ liệu thô không nằm trong repo (điều khoản OpenPhish: "
             "chỉ dùng phi thương mại); script tải lại từ đúng commit đã ghim:", "",
             f"- phishing: OpenPhish Community Feed, lịch sử git `{OPENPHISH_REPO}` tại `{OPENPHISH_COMMIT[:12]}`",
             f"- hợp lệ: Chrome UX Report top 1 triệu origin, `zakird/crux-top-lists` tại `{CRUX_COMMIT[:12]}`", ""]

    # data
    phish_first = phishing_hosts()
    crux = crux_hosts()
    phish_set = set(phish_first)
    benign_pool = [h for h in dict.fromkeys(crux) if h not in phish_set]
    idn_benign = [h for h in benign_pool if "xn--" in h]
    benign = list(dict.fromkeys(rng.sample(benign_pool, BENIGN_SAMPLE) + idn_benign))
    scope = {h: in_scope(h, keywords) for h in phish_first}
    uniform = rng.sample(sorted(phish_first), PHISH_SAMPLE)
    phish = list(dict.fromkeys(uniform + [h for h, s in scope.items() if s]))
    first = min(phish_first.values())
    last = max(phish_first.values())
    fmt = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d")  # noqa: E731
    lines += [f"{len(phish_first):,} host phishing khác nhau, xuất hiện từ {fmt(first)} đến {fmt(last)}; "
              f"{len(benign_pool):,} host hợp lệ.".replace(",", "."), ""]

    scores = score_all(phish + benign)
    p0 = {h: prob(w0, scores[h]) for h in scores}

    # 1. real phishing
    in_scope_hosts = [h for h in phish if scope[h]]
    counts = Counter(scope.values())
    lines += ["## 1. Phishing thật: phạm vi và tỷ lệ phát hiện", "",
              "**Phạm vi** (quy tắc minh bạch, không dùng engine): host có chứa từ khóa của một thương hiệu được bảo vệ "
              "sau khi bỏ dấu chấm / gạch, hoặc host dùng IDN (`xn--` / Unicode).", "",
              "| | số host | tỷ lệ |", "|---|---|---|",
              f"| toàn bộ phishing | {len(phish_first):,} | 100% |".replace(",", "."),
              f"| trong phạm vi: nhắc thương hiệu được bảo vệ | {counts['brand']:,} | "
              f"{pct(counts['brand'] / len(phish_first))} |".replace(",", ".", 1),
              f"| trong phạm vi: IDN | {counts['idn']:,} | {pct(counts['idn'] / len(phish_first))} |".replace(",", ".", 1),
              f"| ngoài phạm vi | {counts[None]:,} | {pct(counts[None] / len(phish_first))} |".replace(",", ".", 1), "",
              "Tỷ lệ gắn cờ (SUSPICIOUS trở lên) theo profile:", "",
              "| tập | default | banking | browser |", "|---|---|---|---|"]
    groups = {"toàn bộ (mẫu ngẫu nhiên)": uniform, "trong phạm vi: thương hiệu": [h for h in in_scope_hosts if scope[h] == "brand"],
              "trong phạm vi: IDN": [h for h in in_scope_hosts if scope[h] == "idn"],
              "ngoài phạm vi (mẫu ngẫu nhiên)": [h for h in uniform if not scope[h]]}
    for label, hosts in groups.items():
        lines.append(f"| {label} | " + " | ".join(
            rate(sum(flagged(p0[h], name=n) for h in hosts), len(hosts)) for n in ("default", "banking", "browser")) + " |")
    by_engine = Counter()
    for h in in_scope_hosts:
        if flagged(p0[h]):
            by_engine[NAMES[max(range(len(NAMES)), key=lambda i: scores[h][i] * w0[i + 1])]] += 1
    missed = [h for h in groups["trong phạm vi: thương hiệu"] if not flagged(p0[h])]
    lines += ["", "Engine đóng góp nhiều nhất cho các phát hiện trong phạm vi: " +
              ", ".join(f"{n} {c:,}".replace(",", ".") for n, c in by_engine.most_common()) + ".", "",
              "Ví dụ bỏ lọt trong phạm vi thương hiệu: " + ", ".join(f"`{h}`" for h in sorted(missed)[:12]) + ".", ""]

    # 2. benign by region
    lines += ["## 2. Báo nhầm trên domain hợp lệ quốc tế và đa ngôn ngữ", "",
              f"{len(benign):,} host hợp lệ: mẫu ngẫu nhiên {BENIGN_SAMPLE:,} từ CrUX top 1 triệu (phân bố thật theo quốc gia) "
              f"cộng toàn bộ {len(idn_benign):,} IDN trong đó.".replace(",", "."), "",
              "| nhóm | số host | FPR default | FPR banking | FPR browser |", "|---|---|---|---|---|"]
    by_region = defaultdict(list)
    for h in benign:
        by_region[region(h)].append(h)
    by_region["IDN (mọi đuôi)"] = idn_benign
    for label, hosts in sorted(by_region.items(), key=lambda kv: -len(kv[1])):
        lines.append(f"| {label} | {len(hosts):,} | ".replace(",", ".") + " | ".join(
            pct(sum(flagged(p0[h], name=n) for h in hosts) / len(hosts)) for n in ("default", "banking", "browser")) + " |")
    fp = sorted((h for h in benign if flagged(p0[h], name="browser")), key=lambda h: -p0[h])
    kinds = Counter()
    for h in benign:
        if flagged(p0[h]):
            kinds[NAMES[max(range(len(NAMES)), key=lambda i: scores[h][i] * w0[i + 1])]] += 1
    lines += ["", "Engine gây báo nhầm (profile default): " + ", ".join(f"{n} {c:,}".replace(",", ".") for n, c in kinds.most_common()) + ".",
              "", "Báo nhầm còn lại ở profile browser: " + ", ".join(f"`{h}`" for h in fp[:15]) + ".", ""]

    # 3. temporal validation
    cut = CUTOFF.timestamp()
    split = lambda h: int(hashlib.sha256(h.encode()).hexdigest(), 16) % 10 >= 7  # noqa: E731
    train = [(h, 1) for h in phish if phish_first[h] < cut] + [(h, 0) for h in benign if not split(h)]
    test = [(h, 1) for h in phish if phish_first[h] >= cut] + [(h, 0) for h in benign if split(h)]
    rand_rows = [(h, 1) for h in phish] + [(h, 0) for h in benign]
    rand_train = [r for r in rand_rows if not split(r[0])]
    rand_test = [r for r in rand_rows if split(r[0])]
    w_time = fit([[1.0, *scores[h]] for h, _ in train], [y for _, y in train])
    w_rand = fit([[1.0, *scores[h]] for h, _ in rand_train], [y for _, y in rand_train])

    def evaluate(w, rows, scope_only=False):
        rows = [(h, y) for h, y in rows if not y or not scope_only or scope[h]]
        y = [yy for _, yy in rows]
        p = [prob(w, scores[h]) for h, _ in rows]
        r1, _ = recall_at_fpr(y, p, 0.01)
        r01, _ = recall_at_fpr(y, p, 0.001)
        return roc_auc(y, p), r1, r01, brier(y, p), reliability(y, p)[1]

    lines += ["## 3. Kiểm định theo thời gian (temporal validation)", "",
              f"Train: phishing xuất hiện trước {CUTOFF:%Y-%m-%d}; test: phishing xuất hiện từ ngày đó "
              f"({sum(y for _, y in test):,} host); domain hợp lệ tách 70/30 cố định. ".replace(",", ".") +
              "So với cách tách ngẫu nhiên (trộn quá khứ và tương lai) để thấy mức lạc quan do rò rỉ thời gian. "
              "Recall ở FPR 1% / 0,1% với ngưỡng chọn trên chính tập test.", "",
              "| mô hình | đánh giá trên | ROC-AUC | recall @ FPR 1% | recall @ FPR 0,1% | Brier | ECE |",
              "|---|---|---|---|---|---|---|"]
    for label, w, rows in [("production (benchmark tổng hợp)", w0, test), ("fit trên quá khứ thật", w_time, test),
                           ("fit tách ngẫu nhiên", w_rand, rand_test)]:
        for scope_only in (False, True):
            auc, r1, r01, b, e = evaluate(w, rows, scope_only)
            lines.append(f"| {label} | {'trong phạm vi' if scope_only else 'toàn bộ'} | {auc:.3f} | {pct(r1)} | "
                         f"{pct(r01)} | {b:.4f} | {e:.4f} |")
    monthly = defaultdict(list)
    for h in in_scope_hosts:
        monthly[datetime.fromtimestamp(phish_first[h], timezone.utc).strftime("%Y-%m")].append(flagged(p0[h]))
    lines += ["", "Recall trong phạm vi theo tháng (mô hình production, profile default), để thấy trôi dạt theo thời gian:", "",
              "| tháng | " + " | ".join(m[2:] for m in sorted(monthly)) + " |",
              "|---|" + "---|" * len(monthly),
              "| recall | " + " | ".join(f"{100 * sum(v) / len(v):.0f}" for _, v in sorted(monthly.items())) + " |",
              "| số host | " + " | ".join(str(len(v)) for _, v in sorted(monthly.items())) + " |", ""]

    # 4. adversarial
    synthetic = [json.loads(line) for line in (ROOT / "benchmark" / "dataset.jsonl").read_text("ascii").splitlines()]
    syn_scores = score_all([r["domain"] for r in synthetic])
    syn_rows = [(syn_scores[r["domain"]], r["label"], r["category"]) for r in synthetic]
    categories = sorted({c for _, y, c in syn_rows if y})
    lines += ["## 4. Kiểm thử adversarial", "",
              "### Bỏ một kỹ thuật khi fit (leave-one-technique-out)", "",
              "Fit lại tầng hợp nhất không có một loại tấn công của benchmark tổng hợp, rồi đo recall trên chính loại đó "
              "(ngưỡng default 0,5). Chênh lệch nhỏ nghĩa là kết quả không phụ thuộc vào việc đã thấy kỹ thuật đó khi fit.", "",
              "| kỹ thuật bị giữ lại | recall khi đã thấy | recall khi chưa thấy |", "|---|---|---|"]
    for cat in categories:
        rest = [(s, y) for s, y, c in syn_rows if c != cat]
        held = [s for s, y, c in syn_rows if c == cat]
        w = fit([[1.0, *s] for s, _ in rest], [y for _, y in rest])
        seen = sum(prob(w0, s) >= 0.5 for s in held) / len(held)
        unseen = sum(prob(w, s) >= 0.5 for s in held) / len(held)
        lines.append(f"| {cat} | {pct(seen)} | {pct(unseen)} |")
    adversarial = build_adversarial()
    adv_scores = score_all([r["input"] for r in adversarial])
    lines += ["", "### Kỹ thuật mới chưa từng dùng khi phát triển", "",
              f"{len(adversarial)} biến thể trong `benchmark/adversarial.jsonl`, sinh từ {len(NOVEL_TECHNIQUES)} kỹ thuật "
              "không có trong dnstwist, golden corpus hay bất kỳ test nào trước đó.", "",
              "| kỹ thuật | mô tả | số mẫu | default | banking | browser |", "|---|---|---|---|---|---|"]
    for name, (desc, _) in NOVEL_TECHNIQUES.items():
        rows = [r["input"] for r in adversarial if r["technique"] == name]
        lines.append(f"| `{name}` | {desc} | {len(rows)} | " + " | ".join(
            pct(sum(flagged(prob(w0, adv_scores[x]), name=n) for x in rows) / len(rows)) for n in ("default", "banking", "browser")) + " |")
    adv_missed = [r["input"] for r in adversarial if not flagged(prob(w0, adv_scores[r["input"]]))]
    lines += ["", "Ví dụ bỏ lọt: " + ", ".join(f"`{x.encode('unicode_escape').decode() if not x.isascii() else x}`"
                                           for x in adv_missed[:12]) + ".", ""]

    # 5. calibration
    model = calibration()
    syn_test = [(s, y) for (s, y, _), r in zip(syn_rows, synthetic)
                if int(hashlib.sha256(r["group"].encode()).hexdigest(), 16) % 10 >= 7]
    y_syn, p_syn = [y for _, y in syn_test], [prob(w0, s) for s, _ in syn_test]
    y_real, p_real = [y for _, y in test], [prob(w0, scores[h]) for h, _ in test]
    real_prior = sum(y_real) / len(y_real)
    p_adj = [at_base_rate(p, real_prior) for p in p_real]
    p_time = [prob(w_time, scores[h]) for h, _ in test]
    curves = {"benchmark tổng hợp, tập test": (y_syn, p_syn), "phishing thật sau mốc, production": (y_real, p_real),
              f"như trên, hiệu chỉnh base rate {real_prior:.2f}": (y_real, p_adj), "phishing thật, fit trên quá khứ": (y_real, p_time)}
    reliability_figure(curves)
    lines += ["## 5. Hiệu chỉnh xác suất (calibration)", "",
              "![Reliability diagram](../docs/img/reliability.svg)", "",
              "| đánh giá | tỷ lệ tấn công | Brier | ECE |", "|---|---|---|---|"]
    for label, (y, p) in curves.items():
        lines.append(f"| {label} | {pct(sum(y) / len(y))} | {brier(y, p):.4f} | {reliability(y, p)[1]:.4f} |")
    prior = model["dataset"]["train_prior"]
    lines += ["", f"Xác suất của mô hình production giả định tỷ lệ tấn công {pct(prior)} (tập train của benchmark). "
              "Precision thật khi triển khai, với recall và FPR đo trên phishing thật sau mốc (profile default):", "",
              "| tỷ lệ tấn công trong lưu lượng | precision trong phạm vi | precision toàn bộ |", "|---|---|---|"]
    neg = [h for h, y in test if not y]
    fpr = sum(flagged(p0[h]) for h in neg) / len(neg)
    pos_all = [h for h, y in test if y]
    pos_scope = [h for h in pos_all if scope[h]]
    rec_all = sum(flagged(p0[h]) for h in pos_all) / len(pos_all)
    rec_scope = sum(flagged(p0[h]) for h in pos_scope) / len(pos_scope)
    for base in (0.1, 0.01, 0.001, 0.0001):
        prec = lambda r: r * base / (r * base + fpr * (1 - base)) if r * base + fpr * (1 - base) else 0  # noqa: E731
        lines.append(f"| {base:g} | {pct(prec(rec_scope))} | {pct(prec(rec_all))} |")
    lines += ["", f"(FPR {pct(fpr)}, recall trong phạm vi {pct(rec_scope)}, toàn bộ {pct(rec_all)}.) "
              "Dùng `--base-rate` để báo cáo xác suất theo tỷ lệ của hệ thống bạn.", ""]

    OUT.write_text("\n".join(lines) + "\n", "utf-8")
    print(OUT.read_text("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
