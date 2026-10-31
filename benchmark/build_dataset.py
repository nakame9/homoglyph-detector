#!/usr/bin/env python3
"""Build benchmark/dataset.jsonl from sources that are independent of this tool.

    pip install dnstwist && python benchmark/build_dataset.py

label 0  benign   OpenDNS top 10,000 domains (github.com/opendns/public-domain-lists)
                  + HARD_NEGATIVES: Vietnamese sites, legitimate IDNs, near-brand real words
label 1  attack   dnstwist permutations of every protected brand domain, all fuzzers, with
                  COMBO_WORDS as the dictionary for combosquats (paypal-login.com, securepaypal.com)
                  + dnstwist IDN homoglyphs of popular *unprotected* domains (brand-agnostic tests)
                  + CURATED_ATTACKS: Unicode tricks dnstwist does not generate (bidi, invisible, ...)

Each row has a "group" (the original domain) so calibrate.py keeps every permutation of one
domain on the same side of the train/test split. Domains are stored JSON-escaped (pure ASCII).
"""
from __future__ import annotations

import json
import random
import sys
import urllib.request
from pathlib import Path

import dnstwist
import idna

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from homoglyph_detector.context import registrable  # noqa: E402
from homoglyph_detector.brands import load_brands  # noqa: E402
from homoglyph_detector.engines import is_official  # noqa: E402

OUT = Path(__file__).resolve().parent / "dataset.jsonl"
OPENDNS = "https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt"
SEED = 2026
PER_FUZZER = 25          # dnstwist makes ~1,200 homoglyphs per domain: cap each fuzzer to balance categories
MIN_LABEL = 4            # 'wa.me' permutations ('aa.me', 'wz.me') are mostly unrelated names, not look-alikes
UNPROTECTED = 150        # popular domains used for brand-agnostic IDN homoglyph attacks
PER_UNPROTECTED = 6

HARD_NEGATIVES = [
    # Vietnamese sites
    "vnexpress.net", "dantri.com.vn", "tuoitre.vn", "thanhnien.vn", "vietnamnet.vn", "znews.vn", "baomoi.com",
    "cafef.vn", "tiki.vn", "lazada.vn", "sendo.vn", "thegioididong.com", "dienmayxanh.com", "fptshop.com.vn",
    "fpt.com.vn", "viettel.vn", "vnpt.vn", "vnpay.vn", "bidv.com.vn", "vpbank.com.vn", "mbbank.com.vn",
    "acb.com.vn", "agribank.com.vn", "tpb.vn", "vib.com.vn", "sacombank.com.vn", "vietinbank.vn", "chinhphu.vn",
    # legitimate IDNs: Vietnamese, European, IANA example IDNs, Cyrillic, CJK
    "ti\u1ebfngvi\u1ec7t.vn", "h\u00e0n\u1ed9i.vn", "m\u00fcnchen.de", "b\u00fccher.de", "stra\u00dfe.de",
    "caf\u00e9.fr", "espa\u00f1a.com", "\u00e5land.fi", "\u0441\u0430\u0439\u0442.\u0440\u0444",
    "\u043f\u0440\u0438\u043c\u0435\u0440.\u0438\u0441\u043f\u044b\u0442\u0430\u043d\u0438\u0435",
    "\u043c\u043e\u0441\u043a\u0432\u0430.\u0440\u0444", "\u4f8b\u5b50.\u6d4b\u8bd5",
    "\u4f8b\u3048.\u30c6\u30b9\u30c8", "\u65e5\u672c\u8a9e.jp", "\u4e2d\u6587\u7f51.cn",
    "\u03c0\u03b1\u03c1\u03ac\u03b4\u03b5\u03b9\u03b3\u03bc\u03b1.\u03b4\u03bf\u03ba\u03b9\u03bc\u03ae",
    "\uc2e4\ub840.\ud14c\uc2a4\ud2b8", "\u0645\u062b\u0627\u0644.\u0625\u062e\u062a\u0628\u0627\u0631",
    # real words close to protected brand names
    "apply.com", "applied.com", "email.com", "ample.com", "shoplee.com", "mono.co", "memo.com", "momoshop.com",
    "amazonas.gov.br", "applebee.com", "outlook.org", "office.org", "googol.com", "youtuber.net",
]

# words commonly prepended/appended to brands in combosquatting domains
COMBO_WORDS = ["login", "signin", "secure", "account", "verify", "support", "update", "help", "service",
               "billing", "wallet", "online", "pay", "app", "id", "auth", "recovery", "confirm", "alert", "security"]

CURATED_ATTACKS = [
    ("bidi", "\u202emoc.lapyap"), ("bidi", "invoice\u202efdp.exe"), ("bidi", "\u2066paypal.com"),
    ("bidi", "apple\u200f.com"),
    ("invisible", "pay\u200bpal.com"), ("invisible", "goo\u00adgle.com"), ("invisible", "micro\u2060soft.com"),
    ("invisible", "face\u200cbook.com"), ("invisible", "ama\u200dzon.com"),
    ("fullwidth", "\uff50\uff41\uff59\uff50\uff41\uff4c.com"), ("fullwidth", "\uff47\uff4f\uff4f\uff47\uff4c\uff45.com"),
    ("whole-script", "\u0430\u0440\u0440\u04cf\u0435.com"), ("whole-script", "\u0455\u04bb\u043e\u0440\u0435\u0435.vn"),
    ("whole-script", "\u0440\u0430\u0443\u0440\u0430\u04cf.com"),
    ("combosquat", "p\u0430ypal-login.com"), ("combosquat", "secure-g\u043e\u043egle.com"),
    ("combosquat", "paypai-verify.com"), ("combosquat", "5hopee-sale.vn"), ("combosquat", "vietcornbank-online.com"),
    ("combosquat", "rnicrosoft-support.com"), ("combosquat", "app1e-id.com"), ("combosquat", "faceb00k-security.com"),
    ("hosting", "p\u0430ypal.github.io"), ("hosting", "vietcornbank.blogspot.com"), ("hosting", "arnazon.web.app"),
    ("display-name", "PayPa1 Support"), ("display-name", "5hopee Official"), ("display-name", "G\u043e\u043egle Security"),
    ("mixed-number", "paypal\u0661.com"), ("hidden-overlay", "appl\u00e9\u0301.com"),
]


def permutations(domain: str, fuzzers: set[str] | None, cap: int, rng: random.Random) -> list[tuple[str, str]]:
    fuzzer = dnstwist.Fuzzer(domain, dictionary=COMBO_WORDS)
    fuzzer.generate()
    by_kind: dict[str, list[str]] = {}
    for item in fuzzer.domains:
        if item["fuzzer"] != "*original" and (fuzzers is None or item["fuzzer"] in fuzzers):
            by_kind.setdefault(item["fuzzer"], []).append(item["domain"])
    return [(kind, d) for kind, items in sorted(by_kind.items()) for d in rng.sample(sorted(items), min(cap, len(items)))]


def main() -> int:
    rng = random.Random(SEED)
    brands = load_brands()
    with urllib.request.urlopen(OPENDNS, timeout=60) as response:
        top = [d.strip().lower() for d in response.read().decode().splitlines() if d.strip()]
    rows, seen = [], set()

    def add(domain: str, label: int, category: str, group: str) -> None:
        if domain not in seen:
            seen.add(domain)
            rows.append({"domain": domain, "label": label, "category": category, "group": group})

    for d in top:
        add(d, 0, "top10k", d)
    for d in HARD_NEGATIVES:
        add(d, 0, "hard-negative", d)
        if not d.isascii():   # benign IDNs also appear in DNS (A-label) form, like the attacks do
            add(idna.encode(d, uts46=True).decode("ascii"), 0, "hard-negative", d)

    official = sorted({d for b in brands for d in b["domains"] if len(registrable(d)[1]) >= MIN_LABEL})
    for domain in official:
        for kind, d in permutations(domain, None, PER_FUZZER, rng):
            if not is_official(d, brands):
                add(d, 1, f"brand/{kind}", domain)
    keywords = [kw for b in brands for kw in b["keywords"]]
    popular = [d for d in top if len(registrable(d)[1]) >= MIN_LABEL and not is_official(d, brands)
               and not any(kw in d for kw in keywords)][:UNPROTECTED]
    for domain in popular:
        homoglyphs = [p for p in permutations(domain, {"homoglyph", "cyrillic"}, 1000, rng) if "xn--" in p[1]]
        for kind, d in rng.sample(homoglyphs, min(PER_UNPROTECTED, len(homoglyphs))):
            add(d, 1, f"unprotected/{kind}", domain)
    for category, d in CURATED_ATTACKS:
        add(d, 1, f"curated/{category}", f"curated:{d}")

    with OUT.open("w", encoding="ascii") as out:
        for row in rows:
            out.write(json.dumps(row, ensure_ascii=True) + "\n")
    positives = sum(r["label"] for r in rows)
    print(f"wrote {len(rows)} rows ({positives} attacks, {len(rows) - positives} benign) to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
