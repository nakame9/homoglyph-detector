"""Orchestrator: prepare the input, run every engine, fuse their scores into a calibrated risk."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .context import Context, classify, prepare, registrable  # noqa: F401  (re-exported)
from .brands import load, resolve
from .engines import ENGINES, EngineResult, Finding
from .scoring import at_base_rate, probability, profile, verdict
from .unicode_data import skeleton


@dataclass
class Report:
    input: str
    input_type: str
    target: str            # what a reader sees: the name, or the host with A-labels shown as U-labels
    skeleton: str
    a_label: str = ""      # the domain as DNS sees it (IDNA2008 A-labels); empty if not a valid domain
    verdict: str = "SAFE"
    probability: float = 0.0    # P(look-alike attack) at the benchmark's base rate; see benchmark/RESULTS.md
    base_rate: float | None = None               # attack share of the deployment, if given
    probability_at_base_rate: float | None = None   # `probability` corrected to that base rate
    risk_score: int = 0         # the probability on a 0-100 scale
    profile: str = "default"    # risk profile that turned the probability into the verdict
    thresholds: dict = field(default_factory=dict)   # its SUSPICIOUS / MALICIOUS probability cut-offs
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


def analyze(raw: str, brand_files: tuple[str, ...] = (), policy: str | dict | None = None,
            base_rate: float | None = None) -> Report:
    """policy: a built-in profile name ('default', 'banking', 'browser', ...; None = $HOMOGLYPH_PROFILE
    or 'default') or a dict from scoring.custom_profile(). base_rate: share of attacks in your traffic;
    adds probability_at_base_rate. The verdict does not change: thresholds are false positive budgets."""
    ctx, results = run_engines(raw, brand_files)
    scores = {name: result.score for name, result in results.items()}
    p = probability(scores)
    policy = policy if isinstance(policy, dict) else profile(policy)
    return Report(input=raw, input_type=ctx.input_type, target=ctx.text, skeleton=skeleton(ctx.text),
                  a_label=ctx.a_label, verdict=verdict(p, policy), probability=round(p, 4), risk_score=round(100 * p),
                  base_rate=base_rate,
                  probability_at_base_rate=None if base_rate is None else round(at_base_rate(p, base_rate), 6),
                  profile=policy["name"],
                  thresholds={level: policy[level] for level in ("suspicious", "malicious")},
                  restriction_level=results["unicode"].facts["restriction_level"], engine_scores=scores,
                  brand_db=[db.info() for db in load(resolve(tuple(brand_files)))[1]],
                  findings=[finding for result in results.values() for finding in result.findings])
