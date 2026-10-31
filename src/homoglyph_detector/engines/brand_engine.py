"""brand engine: identity look-alikes of protected brands (skeleton homographs, one-edit typosquats)."""
from __future__ import annotations

from ..context import Context, registrable
from ..unicode_data import confusable_type, skeleton
from .base import MIN_FUZZY_LEN, EngineResult, is_official, typed


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
            result.add("brand_homograph", "critical", f"Impersonates {name}: renders like '{hit}'{typed(kind)}",
                       brand=name, official=hit, confusable_type=kind)
            continue
        # keywords plus the names of the official domains ('office' from office.com)
        for kw in dict.fromkeys([*brand["keywords"], *(registrable(d)[1] for d in brand["domains"])]):
            kw_skel = skeleton(kw)
            if label_skel == kw_skel and label != kw:
                kind = confusable_type(label, kw)
                result.add("brand_homograph", "high", f"Name '{label}' renders like {name} keyword '{kw}'{typed(kind)}",
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
                               f"'{word}' renders like {brand['name']} keyword '{kw}'{typed(kind)}",
                               brand=brand["name"], keyword=kw, confusable_type=kind)


def brand_engine(ctx: Context, brands: list[dict]) -> EngineResult:
    result = EngineResult("brand")
    if ctx.input_type == "name":
        _brands_name(ctx.text, brands, result)
    elif ctx.host:
        _brands_host(ctx.resolved or ctx.text, brands, result)   # match what is actually visited
    return result.noisy_or()
