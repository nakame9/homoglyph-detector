"""combosquat engine: a brand name reused on an unofficial domain (paypal-login.com, google.ca)."""
from __future__ import annotations

from ..context import Context, registrable
from ..unicode_data import skeleton
from .base import MIN_FUZZY_LEN, EngineResult, is_official


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
