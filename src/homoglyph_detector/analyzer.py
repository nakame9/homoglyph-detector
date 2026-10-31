"""Turn a domain / email / URL / name into findings and a verdict."""
from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import asdict, dataclass, field
from functools import cache
from pathlib import Path
from urllib.parse import urlsplit

import idna
from publicsuffixlist import PublicSuffixList

from .unicode_data import (DATA, LEVELS, confusable_type, is_allowed, is_bidi_control, is_default_ignorable,
                           is_single_script,
                           numbering_systems, repeated_marks, restriction_level, script_of, scripts_in,
                           skeleton)
from .visual import MAX_VISUAL_DISTANCE, VisualMatch, visual_similarity

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
VERDICT = {0: "SAFE", 1: "SAFE", 2: "SUSPICIOUS", 3: "MALICIOUS", 4: "MALICIOUS"}

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
    target: str            # what a reader sees: the name, or the host with A-labels shown as U-labels
    skeleton: str
    a_label: str = ""      # the domain as DNS sees it (IDNA2008 A-labels); empty if not a valid domain
    verdict: str = "SAFE"
    restriction_level: str = "ASCII-Only"   # UTS #39 §5.2, least restrictive part wins
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
        # .hostname would lower-case non-ASCII too; only drop user-info and port.
        return "url", re.sub(r":\d*$", "", urlsplit(raw).netloc.rpartition("@")[2]), ""
    if "@" in raw and " " not in raw:
        local, _, host = raw.rpartition("@")
        return "email", host, local
    if "." in raw and " " not in raw:
        return "domain", raw, ""
    return "name", raw, ""


def shown_host(host: str, report: Report) -> str:
    """The host as a reader sees it: valid A-labels displayed as their U-labels."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                decoded = idna.decode(label)
            except idna.IDNAError:
                pass  # reported by idna_check
            else:
                report.add("punycode", "low", f"A-label '{label}' is the U-label '{decoded}'")
                label = decoded
        labels.append(label)
    return ".".join(labels)


def _idna_error(error: idna.IDNAError) -> tuple[str, str]:
    if isinstance(error, idna.IDNABidiError):
        return "idna_bidi", "breaks the IDNA bidi rule (RFC 5893)"
    if isinstance(error, idna.InvalidCodepointContext):
        return "idna_context", "breaks an IDNA contextual rule (RFC 5892 CONTEXTJ/CONTEXTO)"
    if isinstance(error, idna.InvalidCodepoint):
        return "idna_disallowed", "contains a code point IDNA2008 does not allow"
    if "too long" in str(error):
        return "idna_length", "exceeds DNS length limits (63 octets per label, 253 per domain)"
    return "idna_invalid", "is not a valid IDNA2008 domain name"


def idna_check(host: str, report: Report) -> str:
    """IDNA2008 validation + A-label/U-label conversion. Returns the U-label domain that would
    actually be resolved, or "" when no resolver would accept the input."""
    try:
        report.a_label = idna.encode(host).decode("ascii")                 # strict RFC 5891, no mapping
    except idna.IDNAError as strict:
        try:
            report.a_label = idna.encode(host, uts46=True).decode("ascii")  # browser lookup mapping
        except idna.IDNAError as error:
            kind, why = _idna_error(error)
            report.add(kind, "medium", f"'{host}' {why}: {error}")
            return ""
        report.add("idna_mapped", "low", f"Not valid IDNA2008 as written ({strict}); browsers map it to "
                   f"'{idna.decode(report.a_label)}'", mapped=idna.decode(report.a_label))
    u_label = idna.decode(report.a_label)
    if idna.encode(u_label).decode("ascii") != report.a_label:   # A -> U -> A must be lossless
        report.add("idna_roundtrip", "medium",
                   f"'{report.a_label}' does not round-trip through its U-label '{u_label}'")
    return u_label


@cache
def _psl() -> PublicSuffixList:
    return PublicSuffixList()  # bundled list incl. private suffixes (github.io, blogspot.com, ...)


def registrable(host: str) -> tuple[str, str]:
    """Public Suffix List: ('paypal.com', 'paypal') from 'login.paypal.com',
    ('vietcombank.com.vn', 'vietcombank'), ('x.github.io', 'x')."""
    rd = _psl().privatesuffix(host) or host
    suffix = _psl().publicsuffix(rd)
    return rd, (rd[: -len(suffix) - 1] if suffix and rd != suffix else rd.split(".")[0])


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _typed(kind: str | None) -> str:
    return f" ({kind} confusable)" if kind else ""


def check_characters(text: str, report: Report) -> None:
    """UTS #39 checks per label/word, then per character."""
    if unicodedata.normalize("NFKC", text) != text:
        report.add("compatibility", "medium",
                   "Contains compatibility characters (e.g. fullwidth) that normalise to other text",
                   nfkc=unicodedata.normalize("NFKC", text))

    for part in text.replace("@", ".").replace(" ", ".").split("."):
        level = restriction_level(part)
        if LEVELS.index(level) > LEVELS.index(report.restriction_level):
            report.restriction_level = level
        if level in ("Moderately Restrictive", "Minimally Restrictive") or not is_single_script(part):
            severity = "low" if level == "Moderately Restrictive" else "medium"
            report.add("mixed_script", severity,
                       f"'{part}' mixes scripts: {', '.join(sorted(scripts_in(part)))} (level: {level})",
                       scripts=sorted(scripts_in(part)), restriction_level=level)
        skel = skeleton(part)
        if not part.isascii() and skel.isascii() and skel != part:
            kind = confusable_type(part, skel)
            report.add("whole_lookalike", "medium", f"'{part}' renders like ASCII '{skel}'{_typed(kind)}",
                       looks_like=skel, confusable_type=kind)
        if len(numbering_systems(part)) > 1:
            report.add("mixed_numbers", "medium", f"'{part}' mixes digits from different number systems")
        for mark in repeated_marks(part):
            report.add("hidden_overlay", "medium",
                       f"'{part}' stacks the same mark U+{ord(mark):04X} twice (can hide a character)")

    for pos, ch in enumerate(text):
        info = dict(position=pos, char=ch, codepoint=f"U+{ord(ch):04X}", script=script_of(ch))
        if is_bidi_control(ch):
            report.add("bidi_control", "high",
                       f"Position {pos}: bidi control U+{ord(ch):04X} {unicodedata.name(ch, '')} "
                       "can reorder how the text is displayed", **info)
        elif is_default_ignorable(ch):
            report.add("default_ignorable", "medium",
                       f"Position {pos}: invisible U+{ord(ch):04X} {unicodedata.name(ch, '')}", **info)
        elif ch.isascii():
            continue
        elif skeleton(ch).isascii() and skeleton(ch) != ch:
            report.add("confusable_char", "low",
                       f"Position {pos}: '{ch}' U+{ord(ch):04X} ({script_of(ch)}) looks like '{skeleton(ch)}'",
                       **info, looks_like=skeleton(ch))
        elif not is_allowed(ch) and ch != " ":
            report.add("restricted_char", "low",
                       f"Position {pos}: '{ch}' U+{ord(ch):04X} is outside the UTS #39 identifier profile",
                       **info)


def _visual(report: Report, text: str, brand: str, kw: str) -> bool:
    """ASCII visual look-alike of a brand keyword (5hopee, vvhatsapp, clropbox)."""
    match: VisualMatch = visual_similarity(text if text.isascii() else skeleton(text), kw)
    if match.distance > MAX_VISUAL_DISTANCE or not match.edits:   # identical text is not a look-alike
        return False
    report.add("brand_visual", "high", f"'{text}' looks like {brand} keyword '{kw}' "
               f"(visual similarity {match.score:.2f}: {', '.join(match.edits)})",
               brand=brand, keyword=kw, visual_similarity=match.score, edits=match.edits)
    return True


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
            kind = confusable_type(label, registrable(hit)[1])
            report.add("brand_homograph", "critical", f"Impersonates {name}: renders like '{hit}'{_typed(kind)}",
                       brand=name, official=hit, confusable_type=kind)
            continue
        for kw in brand["keywords"]:
            kw_skel = skeleton(kw)
            if label_skel == kw_skel:
                if label == kw:
                    report.add("brand_unofficial", "medium", f"Uses the {name} name on an unofficial domain '{rd}'",
                               brand=name)
                else:
                    kind = confusable_type(label, kw)
                    report.add("brand_homograph", "high",
                               f"Name '{label}' renders like {name} keyword '{kw}'{_typed(kind)}",
                               brand=name, keyword=kw, confusable_type=kind)
            elif any(_visual(report, part, name, kw) for part in dict.fromkeys([label, *label.split("-")])):
                pass  # also catches 'paypai-login': each hyphen-separated part is compared
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
                if word.lower() == kw:
                    continue
                if skeleton(word) == skeleton(kw):
                    kind = confusable_type(word, kw)
                    report.add("brand_homograph", "high",
                               f"'{word}' renders like {brand['name']} keyword '{kw}'{_typed(kind)}",
                               brand=brand["name"], keyword=kw, confusable_type=kind)
                elif word.isascii():
                    _visual(report, word.lower(), brand["name"], kw)


def analyze(raw: str, brands_path: str | None = None) -> Report:
    brands = load_brands(brands_path)
    input_type, target, local = classify(raw)
    report = Report(input=raw, input_type=input_type, target=target, skeleton="")
    if unicodedata.normalize("NFC", raw.strip()) != raw.strip():
        report.add("not_nfc", "low", "Input was not in Unicode NFC; normalised to NFC (same meaning)")

    if input_type == "name":
        check_characters(target, report)
        check_brands_name(target, brands, report)
    else:
        host = "".join(ch.lower() if ch.isascii() else ch for ch in target).rstrip(".")  # DNS ignores ASCII case
        target = report.target = shown_host(host, report)
        resolved = idna_check(host, report) if host else ""
        check_characters(target, report)
        if local:
            check_characters(local, report)
        if host:
            check_brands_host(resolved or target, brands, report)

    report.skeleton = skeleton(target)
    worst = max((SEVERITY_RANK[f.severity] for f in report.findings), default=0)
    report.verdict = VERDICT[worst]
    return report
