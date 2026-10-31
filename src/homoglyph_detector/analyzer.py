"""Turn a domain / email / URL / name into findings and a verdict."""
from __future__ import annotations

import codecs
import json
import unicodedata
from dataclasses import asdict, dataclass, field
from functools import cache
from pathlib import Path
from urllib.parse import urlsplit

from .unicode_data import DATA, script_of, scripts_in, skeleton

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
VERDICT = {0: "SAFE", 1: "SAFE", 2: "SUSPICIOUS", 3: "MALICIOUS", 4: "MALICIOUS"}

# UTS #39 "Highly Restrictive": these script sets are normal (CJK writing), not mixing.
ALLOWED_SCRIPT_SETS = [
    {"Latin", "Han", "Hiragana", "Katakana"},
    {"Latin", "Han", "Bopomofo"},
    {"Latin", "Han", "Hangul"},
]
# shortcut: tiny public-suffix guess, swap in tldextract/PSL when multi-level TLDs matter.
SECOND_LEVELS = {"com", "net", "org", "edu", "gov", "co", "ac", "or", "ne", "info", "biz"}
MIN_FUZZY_LEN = 5  # shorter brand keywords produce too many fuzzy false positives


@dataclass
class Finding:
    kind: str
    severity: str
    message: str
    detail: dict = field(default_factory=dict)


@dataclass
class Report:
    input: str
    input_type: str
    target: str            # what was analysed after decoding (host or name)
    skeleton: str
    verdict: str = "SAFE"
    findings: list[Finding] = field(default_factory=list)

    def add(self, kind: str, severity: str, message: str, **detail) -> None:
        self.findings.append(Finding(kind, severity, message, detail))

    def to_dict(self) -> dict:
        return asdict(self)


@cache
def load_brands(path: str | None = None) -> list[dict]:
    text = Path(path).read_text("utf-8") if path else (DATA / "brands.json").read_text("utf-8")
    return json.loads(text)["brands"]


def classify(raw: str) -> tuple[str, str, str]:
    """Return (input_type, host_or_name, email_local_part)."""
    raw = unicodedata.normalize("NFC", raw.strip())
    if "://" in raw:
        return "url", (urlsplit(raw).hostname or ""), ""
    if "@" in raw and " " not in raw:
        local, _, host = raw.rpartition("@")
        return "email", host, local
    if "." in raw and " " not in raw:
        return "domain", raw, ""
    return "name", raw, ""


def decode_host(host: str, report: Report) -> str:
    labels = []
    for label in host.lower().rstrip(".").split("."):
        if label.startswith("xn--"):
            try:
                decoded = codecs.decode(label[4:].encode("ascii"), "punycode")
            except (UnicodeError, ValueError):
                decoded = ""
            # A real IDN label has non-ASCII and no control/invisible/unassigned (C*) chars.
            if not decoded or decoded.isascii() or any(unicodedata.category(c)[0] == "C" for c in decoded):
                report.add("punycode", "medium", f"Invalid punycode label '{label}' (not a real IDN)")
                labels.append(label)
                continue
            report.add("punycode", "low", f"Punycode '{label}' decodes to '{decoded}'")
            label = decoded
        labels.append(label)
    return ".".join(labels)


def registrable(host: str) -> tuple[str, str]:
    """('paypal.com', 'paypal') from 'login.paypal.com'."""
    labels = host.split(".")
    n = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVELS else 2
    rd = ".".join(labels[-n:])
    return rd, labels[-n] if len(labels) >= n else labels[0]


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def check_characters(text: str, report: Report) -> None:
    """Script mixing, look-alike characters and compatibility forms, per label/word."""
    if unicodedata.normalize("NFKC", text) != text:
        report.add("compatibility", "medium",
                   "Contains compatibility characters (e.g. fullwidth) that normalise to other text",
                   nfkc=unicodedata.normalize("NFKC", text))

    for part in text.replace("@", ".").replace(" ", ".").split("."):
        scripts = scripts_in(part)
        if len(scripts) > 1 and not any(scripts <= ok for ok in ALLOWED_SCRIPT_SETS):
            report.add("mixed_script", "medium", f"'{part}' mixes scripts: {', '.join(sorted(scripts))}",
                       scripts=sorted(scripts))
        skel = skeleton(part)
        if not part.isascii() and skel.isascii() and skel != part:
            report.add("whole_lookalike", "medium", f"'{part}' renders like ASCII '{skel}'", looks_like=skel)

    for pos, ch in enumerate(text):
        if not ch.isascii() and skeleton(ch).isascii() and skeleton(ch) != ch:
            report.add("confusable_char", "low",
                       f"Position {pos}: '{ch}' U+{ord(ch):04X} ({script_of(ch)}) looks like '{skeleton(ch)}'",
                       position=pos, char=ch, codepoint=f"U+{ord(ch):04X}",
                       script=script_of(ch), looks_like=skeleton(ch))


def check_brands_host(host: str, brands: list[dict], report: Report) -> None:
    rd, label = registrable(host)
    if any(host == d or host.endswith("." + d) for b in brands for d in b["domains"]):
        report.add("allowlisted", "info", f"'{rd}' is an official brand domain")
        return
    host_skel, rd_skel, label_skel = skeleton(host), skeleton(rd), skeleton(label)
    for brand in brands:
        name = brand["name"]
        hit = next((d for d in brand["domains"] if skeleton(d) == rd_skel), None)
        if hit:
            report.add("brand_homograph", "critical", f"Impersonates {name}: renders like '{hit}'",
                       brand=name, official=hit)
            continue
        for kw in brand["keywords"]:
            kw_skel = skeleton(kw)
            if label_skel == kw_skel:
                if label == kw:
                    report.add("brand_unofficial", "medium", f"Uses the {name} name on an unofficial domain '{rd}'",
                               brand=name)
                else:
                    report.add("brand_homograph", "high", f"Name '{label}' renders like {name} keyword '{kw}'",
                               brand=name, keyword=kw)
            elif len(kw) >= MIN_FUZZY_LEN and levenshtein(label_skel, kw_skel) == 1:
                report.add("brand_typosquat", "medium", f"'{label}' is one edit away from {name} keyword '{kw}'",
                           brand=name, keyword=kw)
            elif len(kw) >= MIN_FUZZY_LEN and kw_skel in host_skel:
                report.add("brand_in_host", "medium", f"Contains {name} keyword '{kw}' on unofficial domain '{rd}'",
                           brand=name, keyword=kw)
            else:
                continue
            break  # one brand finding per brand is enough


def check_brands_name(name: str, brands: list[dict], report: Report) -> None:
    for word in name.split():
        for brand in brands:
            for kw in brand["keywords"]:
                if word.lower() != kw and skeleton(word) == skeleton(kw):
                    report.add("brand_homograph", "high", f"'{word}' renders like {brand['name']} keyword '{kw}'",
                               brand=brand["name"], keyword=kw)


def analyze(raw: str, brands_path: str | None = None) -> Report:
    brands = load_brands(brands_path)
    input_type, target, local = classify(raw)
    report = Report(input=raw, input_type=input_type, target=target, skeleton="")

    if input_type == "name":
        check_characters(target, report)
        check_brands_name(target, brands, report)
    else:
        target = report.target = decode_host(target, report)
        check_characters(target, report)
        if local:
            check_characters(local, report)
        if target:
            check_brands_host(target, brands, report)

    report.skeleton = skeleton(target)
    worst = max((SEVERITY_RANK[f.severity] for f in report.findings), default=0)
    report.verdict = VERDICT[worst]
    return report
