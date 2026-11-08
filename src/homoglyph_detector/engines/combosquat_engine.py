"""combosquat engine: a brand name reused on an unofficial domain (paypal-login.com, google.ca),
or put in a URL's userinfo so the link reads as the brand (https://paypal.com@evil.com/)."""
from __future__ import annotations

from ..context import Context, registrable, userinfo_domain
from ..unicode_data import skeleton
from .base import MIN_FUZZY_LEN, EngineResult, is_official


def combosquat_engine(ctx: Context, brands: list[dict]) -> EngineResult:
    result = EngineResult("combosquat")
    host = ctx.resolved or ctx.text
    if ctx.input_type == "name" or not ctx.host or is_official(host, brands):
        return result.noisy_or()
    rd, label = registrable(host)
    fake = userinfo_domain(ctx.userinfo)
    if fake:
        fake_label = skeleton(registrable(fake)[1])
        brand = next((b for b in brands if is_official(fake, [b])
                      or any(skeleton(kw) == fake_label for kw in b["keywords"])), None)
        if brand:
            result.add("brand_in_userinfo", "high",
                       f"URL starts with '{fake}' ({brand['name']}) but goes to '{rd}': the part before '@' is "
                       "only a user name", brand=brand["name"], shown=fake, basis="name")
    plain = host.replace(".", "").replace("-", "")   # also 'am.azon.com', 'pay-pal-login'
    squashed = skeleton(plain)
    for brand in brands:
        for kw in brand["keywords"]:
            if label == kw:
                result.add("brand_unofficial", "medium", f"Uses the {brand['name']} name on an unofficial domain '{rd}'",
                           brand=brand["name"], basis="name")
                break
            if len(kw) >= MIN_FUZZY_LEN and skeleton(kw) in squashed and skeleton(label) != skeleton(kw):
                result.add("brand_in_host", "medium",
                           f"Contains {brand['name']} keyword '{kw}' on unofficial domain '{rd}'",
                           brand=brand["name"], keyword=kw,
                           basis="name" if kw in plain else "visual")   # 'rnicrosoft-login' only via rn ~ m
                break
    return result.noisy_or()
