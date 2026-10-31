"""Shared types for the engines: Finding, EngineResult (score + evidence) and small helpers."""
from __future__ import annotations

from dataclasses import dataclass, field

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


def typed(kind: str | None) -> str:
    return f" ({kind} confusable)" if kind else ""
