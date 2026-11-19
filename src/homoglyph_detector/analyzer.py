"""Orchestrator: prepare the input, run every engine, fuse their scores into a calibrated risk."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .context import REASONS, Context, classify, prepare, registrable  # noqa: F401  (re-exported)
from .context import url_metadata
from .brands import load, resolve
from .engines import ENGINES, EngineResult, Finding
from .scoring import at_base_rate, evidence_rule, evidence_summary, probability, profile, verdict
from .unicode_data import skeleton

# Bidi embedding, override and isolate controls (UAX #9): reorder what a reader sees, so they are evidence even
# in a host a browser rejects (P1-b). LRM / RLM / ALM only affect neutral characters and are left out.
BIDI_FORMATTING = frozenset(map(chr, (*range(0x202A, 0x202F), *range(0x2066, 0x206A))))


@dataclass
class Report:
    input: str
    input_type: str
    target: str            # what a reader sees: the name, or the host with A-labels shown as U-labels
    skeleton: str
    a_label: str = ""      # the domain as DNS sees it (IDNA2008 A-labels); empty if not a valid domain
    parse_status: str = "ok"    # 'rejected' or 'unsupported' means the destination was not scored
    parse_reason: str = ""      # why the input needs review when parse_status is not ok
    verdict: str = "SAFE"
    verdict_note: str = ""      # why the verdict differs from the probability's, e.g. capped visual-only evidence
    probability: float = 0.0    # P(look-alike attack) at the benchmark's base rate; see benchmark/RESULTS.md
    base_rate: float | None = None               # attack share of the deployment, if given
    probability_at_base_rate: float | None = None   # `probability` corrected to that base rate
    risk_score: int = 0         # the probability on a 0-100 scale
    profile: str = "default"    # risk profile that turned the probability into the verdict
    thresholds: dict = field(default_factory=dict)   # its SUSPICIOUS / MALICIOUS probability cut-offs
    restriction_level: str = "ASCII-Only"   # UTS #39 §5.2, least restrictive part wins
    engine_scores: dict[str, float] = field(default_factory=dict)   # raw 0..1 score of every engine
    evidence: dict[str, str] = field(default_factory=dict)  # unicode_confusable / visual_similarity /
                                                            # brand_impersonation (+ brand_basis) / protocol
    brand_db: list[dict] = field(default_factory=list)  # brand databases used: name, version, sha256, verification
    findings: list[Finding] = field(default_factory=list)          # evidence, tagged with its engine

    def to_dict(self) -> dict:
        return asdict(self)

    def to_integration_dict(self) -> dict:
        """Versioned report containing only the destination and fixed finding codes."""
        # ponytail: reuse the bounded parser for metadata; engines are not run a second time.
        ctx = None if self.parse_reason == "too_long" else prepare(self.input)
        scheme, port, userinfo, query = url_metadata(ctx) if ctx else (None, None, None, None)
        host = (ctx.ip or ctx.a_label or None) if ctx and self.parse_status == "ok" else None
        port = port if host else None
        destination = host
        if host and scheme:
            authority = f"[{host}]" if ":" in host else host
            destination = f"{scheme}://{authority}" + (f":{port}" if port is not None else "")
        findings = [{"kind": f.kind, **({"brand_id": f.detail["brand_id"]}
                    if f.kind == "brand_in_userinfo" and "brand_id" in f.detail else {})} for f in self.findings]
        return {"schema_version": 1, "input": destination, "input_type": self.input_type,
                "scheme": scheme, "host": host, "port": port, "has_userinfo": userinfo, "has_query": query,
                "parse_status": self.parse_status, "parse_reason": self.parse_reason,
                "verdict": self.verdict, "risk_score": self.risk_score, "findings": findings}


def run_engines(raw: str, brand_files: tuple[str, ...] = ()) -> tuple[Context, dict[str, EngineResult]]:
    """brand_files: extra brand databases ('path' or 'path#sha256=HEX'), after HOMOGLYPH_BRANDS."""
    ctx, (brands, _) = prepare(raw), load(resolve(tuple(brand_files)))
    if ctx.parse_status == "unsupported":
        return ctx, {name: EngineResult(name) for name in ENGINES}
    return ctx, {name: engine(ctx, brands) for name, engine in ENGINES.items()}


def analyze(raw: str, brand_files: tuple[str, ...] = (), policy: str | dict | None = None,
            base_rate: float | None = None) -> Report:
    """policy: a built-in profile name ('default', 'banking', 'browser', ...; None = $HOMOGLYPH_PROFILE
    or 'default') or a dict from scoring.custom_profile(). base_rate: share of attacks in your traffic;
    adds probability_at_base_rate. The verdict does not change: thresholds are false positive budgets.
    MALICIOUS needs evidence beyond visual similarity (scoring.evidence_rule).
    A URL a browser rejects (parse_status 'rejected') is not scored and comes out SUSPICIOUS for review; only a
    bidi formatting control in its host is scored, from that evidence alone, against the policy's thresholds."""
    ctx, results = run_engines(raw, brand_files)
    policy = policy if isinstance(policy, dict) else profile(policy)
    if ctx.parse_status == "ok":
        scores = {name: result.score for name, result in results.items()}
        findings = [finding for result in results.values() for finding in result.findings]
        p = probability(scores)
        level, note = evidence_rule(verdict(p, policy), findings)
        if ctx.ip_obfuscated and level == "SAFE":
            level, note = "SUSPICIOUS", "an IP address written in an unusual form hides where the link goes"
    else:   # P1: the target is unknown; keep the Unicode findings on the host as diagnostics
        diagnostics = results["unicode"].findings
        bidi = [f for f in diagnostics if f.kind == "bidi_control" and f.detail["char"] in BIDI_FORMATTING]
        scores = {name: 0.0 for name in results}
        scores["unicode"] = EngineResult("unicode", findings=bidi).noisy_or().score
        p = probability(scores) if bidi else 0.0   # P1-b: scored from the bidi evidence alone
        level, note = evidence_rule(verdict(p, policy), bidi) if bidi else ("SAFE", "")
        reason = REASONS[ctx.parse_reason]
        if ctx.parse_reason == "too_long":
            findings = [Finding("idna", "input_too_long", "info", reason, {"reason": ctx.parse_reason}, "protocol")]
        else:
            findings = [Finding("idna", "url_rejected", "info", f"Browsers reject this input: {reason}",
                                {"reason": ctx.parse_reason}, "protocol"), *diagnostics]
        note = ("bidi formatting control in the host; " if bidi else "") + \
            f"needs review: {reason}, so the destination was not scored"
        if level == "SAFE":
            level = "SUSPICIOUS"
    return Report(input=ctx.raw, input_type=ctx.input_type, target=ctx.text, skeleton=skeleton(ctx.text),
                  a_label=ctx.a_label, parse_status=ctx.parse_status, parse_reason=ctx.parse_reason,
                  verdict=level, verdict_note=note, probability=round(p, 4),
                  risk_score=round(100 * p), evidence=evidence_summary(findings),
                  base_rate=base_rate,
                  probability_at_base_rate=None if base_rate is None or ctx.parse_status != "ok"
                  else round(at_base_rate(p, base_rate), 6),
                  profile=policy["name"],
                  thresholds={level: policy[level] for level in ("suspicious", "malicious")},
                  restriction_level=results["unicode"].facts.get("restriction_level", "ASCII-Only"), engine_scores=scores,
                  brand_db=[db.info() for db in load(resolve(tuple(brand_files)))[1]],
                  findings=findings)
