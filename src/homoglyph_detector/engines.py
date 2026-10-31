"""Independent detection engines. Each reads the shared Context and returns its own score + evidence.

    unicode  UTS #39: scripts, restriction levels, confusable characters, bidi / invisible characters
    idna     IDNA2008 / UTS #46: validity, mapping, A-label <-> U-label round-trip
    brand       identity look-alikes of protected brands: skeleton homographs, one-edit typosquats
    combosquat  a brand name reused on an unofficial domain (paypal-login.com, google.ca, am.azon.com)
    visual      ASCII visual look-alikes of brand keywords (5hopee, vvhatsapp), continuous similarity

No engine reads another engine's output; scoring.py fuses their scores.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field

import idna

from .context import Context, registrable
from .unicode_data import (LEVELS, confusable_type, is_allowed, is_bidi_control, is_default_ignorable,
                           is_single_script, numbering_systems, repeated_marks, restriction_level, script_of,
                           scripts_in, skeleton)
from .visual import MAX_VISUAL_DISTANCE, visual_similarity

# Raw engine score = noisy-OR of its findings; scoring.py calibrates how much each engine counts.
SEVERITY_WEIGHT = {"info": 0.0, "low": 0.15, "medium": 0.5, "high": 0.8, "critical": 0.95}
MIN_FUZZY_LEN = 5  # shorter brand keywords produce too many fuzzy false positives


@dataclass
class Finding:
    engine: str
    kind: str
    severity: str
    message: str
    detail: dict = field(default_factory=dict)


@dataclass
class EngineResult:
    name: str
    score: float = 0.0              # 0..1, uncalibrated evidence strength
    findings: list[Finding] = field(default_factory=list)
    facts: dict = field(default_factory=dict)   # non-scoring outputs, e.g. the restriction level

    def add(self, kind: str, severity: str, message: str, **detail) -> None:
        self.findings.append(Finding(self.name, kind, severity, message, detail))

    def noisy_or(self) -> EngineResult:
        """Noisy-OR over finding kinds; repeats of one kind (six confusable letters) count once."""
        strongest: dict[str, float] = {}
        for finding in self.findings:
            strongest[finding.kind] = max(strongest.get(finding.kind, 0.0), SEVERITY_WEIGHT[finding.severity])
        clean = 1.0
        for weight in strongest.values():
            clean *= 1 - weight
        self.score = round(1 - clean, 4)
        return self


def is_official(host: str, brands: list[dict]) -> bool:
    return any(host == d or host.endswith("." + d) for b in brands for d in b["domains"])


def _typed(kind: str | None) -> str:
    return f" ({kind} confusable)" if kind else ""


# --- unicode ------------------------------------------------------------------

def _check_characters(text: str, result: EngineResult) -> None:
    if unicodedata.normalize("NFKC", text) != text:
        result.add("compatibility", "medium",
                   "Contains compatibility characters (e.g. fullwidth) that normalise to other text",
                   nfkc=unicodedata.normalize("NFKC", text))

    for part in text.replace("@", ".").replace(" ", ".").split("."):
        level = restriction_level(part)
        if LEVELS.index(level) > LEVELS.index(result.facts["restriction_level"]):
            result.facts["restriction_level"] = level
        if level in ("Moderately Restrictive", "Minimally Restrictive") or not is_single_script(part):
            severity = "low" if level == "Moderately Restrictive" else "medium"
            result.add("mixed_script", severity,
                       f"'{part}' mixes scripts: {', '.join(sorted(scripts_in(part)))} (level: {level})",
                       scripts=sorted(scripts_in(part)), restriction_level=level)
        skel = skeleton(part)
        if not part.isascii() and skel.isascii() and skel != part:
            kind = confusable_type(part, skel)
            result.add("whole_lookalike", "medium", f"'{part}' renders like ASCII '{skel}'{_typed(kind)}",
                       looks_like=skel, confusable_type=kind)
        if len(numbering_systems(part)) > 1:
            result.add("mixed_numbers", "medium", f"'{part}' mixes digits from different number systems")
        for mark in repeated_marks(part):
            result.add("hidden_overlay", "medium",
                       f"'{part}' stacks the same mark U+{ord(mark):04X} twice (can hide a character)")

    for pos, ch in enumerate(text):
        info = dict(position=pos, char=ch, codepoint=f"U+{ord(ch):04X}", script=script_of(ch))
        if is_bidi_control(ch):
            result.add("bidi_control", "high",
                       f"Position {pos}: bidi control U+{ord(ch):04X} {unicodedata.name(ch, '')} "
                       "can reorder how the text is displayed", **info)
        elif is_default_ignorable(ch):
            result.add("default_ignorable", "medium",
                       f"Position {pos}: invisible U+{ord(ch):04X} {unicodedata.name(ch, '')}", **info)
        elif ch.isascii():
            continue
        elif skeleton(ch).isascii() and skeleton(ch) != ch:
            # info: a Cyrillic 'а' inside a Russian word is just Russian; the evidence is at label level
            result.add("confusable_char", "info",
                       f"Position {pos}: '{ch}' U+{ord(ch):04X} ({script_of(ch)}) looks like '{skeleton(ch)}'",
                       **info, looks_like=skeleton(ch))
        elif not is_allowed(ch) and ch != " ":
            result.add("restricted_char", "low",
                       f"Position {pos}: '{ch}' U+{ord(ch):04X} is outside the UTS #39 identifier profile",
                       **info)


def unicode_engine(ctx: Context, brands: list[dict]) -> EngineResult:
    result = EngineResult("unicode", facts={"restriction_level": "ASCII-Only"})
    _check_characters(ctx.text, result)
    if ctx.local:
        _check_characters(ctx.local, result)
    return result.noisy_or()


# --- idna ---------------------------------------------------------------------

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


def idna_engine(ctx: Context, brands: list[dict]) -> EngineResult:
    result = EngineResult("idna")
    if unicodedata.normalize("NFC", ctx.raw.strip()) != ctx.raw.strip():
        result.add("not_nfc", "low", "Input was not in Unicode NFC; normalised to NFC (same meaning)")
    if not ctx.host:
        return result.noisy_or()
    for label in ctx.host.split("."):
        if label.startswith("xn--"):
            try:
                result.add("punycode", "info", f"A-label '{label}' is the U-label '{idna.decode(label)}'")
            except idna.IDNAError:
                pass  # reported below through the lookup error
    if ctx.lookup_error:
        kind, why = _idna_error(ctx.lookup_error)
        result.add(kind, "medium", f"'{ctx.host}' {why}: {ctx.lookup_error}")
    elif ctx.strict_error:
        result.add("idna_mapped", "low", f"Not valid IDNA2008 as written ({ctx.strict_error}); browsers map it "
                   f"to '{ctx.resolved}'", mapped=ctx.resolved)
    if ctx.a_label and idna.encode(idna.decode(ctx.a_label)).decode("ascii") != ctx.a_label:
        result.add("idna_roundtrip", "medium",
                   f"'{ctx.a_label}' does not round-trip through its U-label '{idna.decode(ctx.a_label)}'")
    return result.noisy_or()


# --- brand --------------------------------------------------------------------

def edit_distance(a: str, b: str) -> int:
    """Optimal string alignment: insert, delete, substitute, or swap two adjacent characters."""
    d = [[i + j if not i * j else 0 for j in range(len(b) + 1)] for i in range(len(a) + 1)]
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] != b[j - 1]))
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def _brands_host(host: str, brands: list[dict], result: EngineResult) -> None:
    rd, label = registrable(host)
    if is_official(host, brands):
        result.add("allowlisted", "info", f"'{rd}' is an official brand domain")
        return
    rd_skel, label_skel = skeleton(rd), skeleton(label)
    for brand in brands:
        name = brand["name"]
        hit = next((d for d in brand["domains"] if skeleton(d) == rd_skel), None)
        if hit:
            kind = confusable_type(label, registrable(hit)[1])
            result.add("brand_homograph", "critical", f"Impersonates {name}: renders like '{hit}'{_typed(kind)}",
                       brand=name, official=hit, confusable_type=kind)
            continue
        # keywords plus the names of the official domains ('office' from office.com)
        for kw in dict.fromkeys([*brand["keywords"], *(registrable(d)[1] for d in brand["domains"])]):
            kw_skel = skeleton(kw)
            if label_skel == kw_skel and label != kw:
                kind = confusable_type(label, kw)
                result.add("brand_homograph", "high", f"Name '{label}' renders like {name} keyword '{kw}'{_typed(kind)}",
                           brand=name, keyword=kw, confusable_type=kind)
                break
            # raw and skeleton forms: the skeleton alone turns 'amazon' into 'arnazon' and hides 'aazon'
            if len(kw) >= MIN_FUZZY_LEN and min(edit_distance(label, kw), edit_distance(label_skel, kw_skel)) == 1:
                result.add("brand_typosquat", "medium", f"'{label}' is one edit away from {name} keyword '{kw}'",
                           brand=name, keyword=kw)
                break


def _brands_name(name: str, brands: list[dict], result: EngineResult) -> None:
    for word in name.split():
        for brand in brands:
            for kw in brand["keywords"]:
                if word.lower() != kw and skeleton(word) == skeleton(kw):
                    kind = confusable_type(word, kw)
                    result.add("brand_homograph", "high",
                               f"'{word}' renders like {brand['name']} keyword '{kw}'{_typed(kind)}",
                               brand=brand["name"], keyword=kw, confusable_type=kind)


def brand_engine(ctx: Context, brands: list[dict]) -> EngineResult:
    result = EngineResult("brand")
    if ctx.input_type == "name":
        _brands_name(ctx.text, brands, result)
    elif ctx.host:
        _brands_host(ctx.resolved or ctx.text, brands, result)   # match what is actually visited
    return result.noisy_or()


# --- combosquat ---------------------------------------------------------------

def combosquat_engine(ctx: Context, brands: list[dict]) -> EngineResult:
    result = EngineResult("combosquat")
    host = ctx.resolved or ctx.text
    if ctx.input_type == "name" or not ctx.host or is_official(host, brands):
        return result.noisy_or()
    rd, label = registrable(host)
    squashed = skeleton(host).replace(".", "").replace("-", "")   # also 'am.azon.com', 'pay-pal-login'
    for brand in brands:
        for kw in brand["keywords"]:
            if label == kw:
                result.add("brand_unofficial", "medium", f"Uses the {brand['name']} name on an unofficial domain '{rd}'",
                           brand=brand["name"])
                break
            if len(kw) >= MIN_FUZZY_LEN and skeleton(kw) in squashed and skeleton(label) != skeleton(kw):
                result.add("brand_in_host", "medium",
                           f"Contains {brand['name']} keyword '{kw}' on unofficial domain '{rd}'",
                           brand=brand["name"], keyword=kw)
                break
    return result.noisy_or()


# --- visual -------------------------------------------------------------------

def visual_engine(ctx: Context, brands: list[dict]) -> EngineResult:
    """Score = best (1 - weighted visual distance) to any brand keyword; a finding when it is a look-alike."""
    result = EngineResult("visual")
    if ctx.input_type == "name":
        parts = [word.lower() for word in ctx.text.split()]
    elif ctx.host and not is_official(ctx.resolved or ctx.text, brands):
        label = registrable(ctx.resolved or ctx.text)[1]
        parts = [label, *label.split("-")]   # also 'paypai-login': each hyphen-separated part
    else:
        return result
    best = 0.0
    for part in dict.fromkeys(p for p in parts if p):
        for brand in brands:
            for kw in brand["keywords"]:
                match = visual_similarity(part, kw)
                if not match.edits:      # identical text is not a look-alike
                    continue
                best = max(best, 1 - match.distance)
                if match.distance <= MAX_VISUAL_DISTANCE:
                    result.add("brand_visual", "high", f"'{part}' looks like {brand['name']} keyword '{kw}' "
                               f"(visual similarity {match.score:.2f}: {', '.join(match.edits)})",
                               brand=brand["name"], keyword=kw, visual_similarity=match.score, edits=match.edits)
    result.score = round(best, 4)
    return result


ENGINES = {"unicode": unicode_engine, "idna": idna_engine, "brand": brand_engine,
           "combosquat": combosquat_engine, "visual": visual_engine}
