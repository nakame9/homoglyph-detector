import pytest

from homoglyph_detector import analyze
from homoglyph_detector.unicode_data import skeleton
from homoglyph_detector.visual import DOMAIN_CHARS, MAX_VISUAL_DISTANCE, NEAR, _costs, visual_similarity


@pytest.mark.parametrize("a, b, edits", [
    ("5hopee", "shopee", ["5->s"]),            # A. character substitution
    ("paypai", "paypal", ["i->l"]),
    ("qoogle", "google", ["q->g"]),
    ("vvhatsapp", "whatsapp", ["vv->w"]),      # B. multi-character substitution
    ("clropbox", "dropbox", ["cl->d"]),
    ("nnicrosoft", "microsoft", ["nn->m"]),
    ("rnicr0s0ft", "microsoft", ["rn->m", "0->o", "0->o"]),   # UTS #39 identical pairs cost nothing
])
def test_visual_lookalikes(a, b, edits):
    match = visual_similarity(a, b)
    assert match.edits == edits and 0 <= match.distance <= MAX_VISUAL_DISTANCE and match.score > 0.9


@pytest.mark.parametrize("a, b", [
    ("paypak", "paypal"),        # a typo, not a look-alike
    ("shoppe", "shopee"),
    ("vietconbank", "vietcombank"),   # n/m alone is too different
    ("example", "paypal"),
])
def test_plain_typos_are_not_visual(a, b):
    assert visual_similarity(a, b).distance > MAX_VISUAL_DISTANCE


def test_c_scoring_is_symmetric_and_bounded():
    for a, b in [("5hopee", "shopee"), ("vvhatsapp", "whatsapp"), ("xyz", "paypal"), ("", "abc")]:
        forward, backward = visual_similarity(a, b), visual_similarity(b, a)
        assert forward.distance == backward.distance and 0 <= forward.score <= 1
    assert visual_similarity("paypal", "paypal") == (1.0, 0.0, [])


def test_near_table_complements_the_official_data():
    for (x, y), similarity in NEAR.items():
        assert set(x + y) <= DOMAIN_CHARS and 0 < similarity < 1
        assert skeleton(x) != skeleton(y), f"{x}/{y} is identical in UTS #39 now: remove it from NEAR"
        assert (y, x) not in NEAR
    identical = {pair for pair, cost in _costs().items() if cost == 0}
    assert {("0", "o"), ("1", "l"), ("m", "rn")} <= identical
    assert ("i", "l") not in identical          # 'I'/'l' are identical only in upper case


@pytest.mark.parametrize("raw", [
    "5hopee.vn", "paypai.com", "vvhatsapp.com", "clropbox.com", "nnicrosoft.com",
    "paypai-login.com",           # look-alike inside a longer label
    "5hopee Official",            # display name / username
])
def test_brand_visual_lookalikes_are_malicious(raw):
    report = analyze(raw)
    assert report.verdict == "MALICIOUS" and "brand_visual" in {f.kind for f in report.findings}


def test_plain_typo_stays_a_typosquat():
    kinds = {f.kind for f in analyze("vietconbank.com.vn").findings}
    assert "brand_typosquat" in kinds and "brand_visual" not in kinds
