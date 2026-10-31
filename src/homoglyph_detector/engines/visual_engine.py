"""visual engine: ASCII / accent look-alikes of brand keywords (5hopee, vvhatsapp), continuous score."""
from __future__ import annotations

from ..context import Context, registrable
from ..visual import MAX_VISUAL_DISTANCE, visual_similarity
from .base import EngineResult, is_official


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
