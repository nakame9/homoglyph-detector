"""Orchestrator: prepare the input, run every engine, fuse their scores into a calibrated risk."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .context import Context, classify, prepare, registrable  # noqa: F401  (re-exported)
from .brands import load, resolve
from .engines import ENGINES, EngineResult, Finding
from .scoring import probability, verdict
from .unicode_data import skeleton


@dataclass
class Report:
    input: str
    input_type: str
    target: str            # what a reader sees: the name, or the host with A-labels shown as U-labels
    skeleton: str
    a_label: str = ""      # the domain as DNS sees it (IDNA2008 A-labels); empty if not a valid domain
    verdict: str = "SAFE"
    probability: float = 0.0    # calibrated P(look-alike attack); see benchmark/RESULTS.md
    risk_score: int = 0         # the probability on a 0-100 scale
    restriction_level: str = "ASCII-Only"   # UTS #39 §5.2, least restrictive part wins
    engine_scores: dict[str, float] = field(default_factory=dict)   # raw 0..1 score of every engine
    brand_db: list[dict] = field(default_factory=list)  # brand databases used: name, version, sha256, verification
    findings: list[Finding] = field(default_factory=list)          # evidence, tagged with its engine

    def to_dict(self) -> dict:
        return asdict(self)


def run_engines(raw: str, brand_files: tuple[str, ...] = ()) -> tuple[Context, dict[str, EngineResult]]:
    """brand_files: extra brand databases ('path' or 'path#sha256=HEX'), after HOMOGLYPH_BRANDS."""
    ctx, (brands, _) = prepare(raw), load(resolve(tuple(brand_files)))
    return ctx, {name: engine(ctx, brands) for name, engine in ENGINES.items()}


def analyze(raw: str, brand_files: tuple[str, ...] = ()) -> Report:
    ctx, results = run_engines(raw, brand_files)
    scores = {name: result.score for name, result in results.items()}
    p = probability(scores)
    return Report(input=raw, input_type=ctx.input_type, target=ctx.text, skeleton=skeleton(ctx.text),
                  a_label=ctx.a_label, verdict=verdict(p), probability=round(p, 4), risk_score=round(100 * p),
                  restriction_level=results["unicode"].facts["restriction_level"], engine_scores=scores,
                  brand_db=[db.info() for db in load(resolve(tuple(brand_files)))[1]],
                  findings=[finding for result in results.values() for finding in result.findings])
