"""Shared types for the engines: Finding, EngineResult (score + evidence) and small helpers."""
from __future__ import annotations

from dataclasses import dataclass, field

# Raw engine score = noisy-OR of its findings; scoring.py calibrates how much each engine counts.
SEVERITY_WEIGHT = {"info": 0.0, "low": 0.15, "medium": 0.5, "high": 0.8, "critical": 0.95}
MIN_FUZZY_LEN = 5  # shorter brand keywords produce too many fuzzy false positives

# What a finding is evidence of. Kept apart because they are not equally reliable:
UNICODE = "unicode_confusable"     # Unicode data: other-script look-alikes, invisible / bidi characters
VISUAL = "visual_similarity"       # looks alike in common fonts (rn/m, 0/o, 5/s, vv/w, dropped accents):
                                   # depends on font, size, kerning and renderer, so it only supports a verdict
BRAND = "brand_impersonation"      # relates to a protected brand; detail['basis'] says on what grounds
PROTOCOL = "protocol"              # IDNA / encoding validity, not a resemblance
ENGINE_EVIDENCE = {"unicode": UNICODE, "idna": PROTOCOL, "brand": BRAND, "combosquat": BRAND, "visual": VISUAL}
STRONG = ("medium", "high", "critical")


@dataclass
class Finding:
    engine: str
    kind: str
    severity: str
    message: str
    detail: dict = field(default_factory=dict)
    evidence: str = ""             # UNICODE, VISUAL, BRAND or PROTOCOL

    @property
    def rests_on_visual(self) -> bool:
        """Visual similarity, or a brand match that only holds through visual similarity."""
        return self.evidence == VISUAL or self.detail.get("basis") == "visual"


@dataclass
class EngineResult:
    name: str
    score: float = 0.0              # 0..1, uncalibrated evidence strength
    findings: list[Finding] = field(default_factory=list)
    facts: dict = field(default_factory=dict)   # non-scoring outputs, e.g. the restriction level

    def add(self, kind: str, severity: str, message: str, **detail) -> None:
        self.findings.append(Finding(self.name, kind, severity, message, detail, ENGINE_EVIDENCE.get(self.name, "")))

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


def resemblance_basis(text: str) -> str:
    """Why `text` resembles a brand: an other-script / non-ASCII confusable is Unicode evidence;
    an all-ASCII look-alike ('rnicrosoft', 'g00gle'), even one listed in confusables.txt, is visual."""
    return "visual" if text.isascii() else "unicode"


def typed(kind: str | None) -> str:
    return f" ({kind} confusable)" if kind else ""
