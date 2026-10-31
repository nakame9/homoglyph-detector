"""Property-based tests and Unicode fuzzing (Hypothesis).

Each test states something that must hold for *every* input, and Hypothesis searches for a
counter-example. Example counts come from the profile in tests/conftest.py.
"""
import json
import string
import unicodedata

from hypothesis import assume, given
from hypothesis import strategies as st

from homoglyph_detector import analyze
from homoglyph_detector.analyzer import run_engines
from homoglyph_detector.brands import load_brands
from homoglyph_detector.cli import render
from homoglyph_detector.context import prepare, registrable
from homoglyph_detector.engines import ENGINES
from homoglyph_detector.engines.brand_engine import edit_distance
from homoglyph_detector.scoring import probability
from homoglyph_detector.unicode_data import _confusables, is_bidi_control, is_default_ignorable, script_of, skeleton
from homoglyph_detector.visual import DOMAIN_CHARS, visual_similarity

VERDICTS = {"SAFE", "SUSPICIOUS", "MALICIOUS"}
INVISIBLE = [chr(c) for c in (0x200B, 0x200C, 0x200D, 0x2060, 0x00AD, 0xFEFF, 0x180E)]
BIDI = [chr(c) for c in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F, 0x061C)]
OFFICIAL = sorted({d for b in load_brands() for d in b["domains"] if len(registrable(d)[1]) >= 4})
# Cyrillic / Greek letters that UTS #39 says look exactly like a given ASCII letter
LOOKALIKE = {}
for src, target in _confusables().items():
    if len(src) == 1 and target in string.ascii_lowercase and script_of(src) in ("Cyrillic", "Greek") and src.islower():
        LOOKALIKE.setdefault(target, []).append(src)
VIETNAMESE = sorted({unicodedata.normalize("NFC", base + tone)
                     for base in "a\u0103\u00e2e\u00eaio\u00f4\u01a1u\u01b0y" for tone in ("", "\u0300", "\u0301", "\u0303", "\u0309", "\u0323")}
                    | set("bcd\u0111ghklmnpqrstvx"))

LABEL_CHARS = st.one_of(
    st.sampled_from(string.ascii_lowercase + string.digits + "-"),
    st.characters(min_codepoint=0x0370, max_codepoint=0x04FF),     # Greek, Cyrillic
    st.characters(min_codepoint=0x0300, max_codepoint=0x036F),     # combining marks
    st.characters(min_codepoint=0x0590, max_codepoint=0x06FF),     # Hebrew, Arabic (right-to-left)
    st.characters(min_codepoint=0x3040, max_codepoint=0x30FF),     # Hiragana, Katakana
    st.characters(min_codepoint=0x4E00, max_codepoint=0x4E40),     # Han
    st.characters(min_codepoint=0xFF00, max_codepoint=0xFF5E),     # fullwidth
    st.sampled_from(VIETNAMESE + INVISIBLE + BIDI),
)
LABELS = st.text(LABEL_CHARS, min_size=1, max_size=15)
DOMAINS = st.builds(lambda labels, tld: ".".join([*labels, tld]), st.lists(LABELS, min_size=1, max_size=3),
                    st.sampled_from(["com", "vn", "com.vn", "co.uk", "github.io", "\u0440\u0444", "xn--p1ai"]))
URL_PARTS = st.text(st.sampled_from(string.ascii_letters + string.digits + "-._~/?#=&%@:"), max_size=20)


def check(raw: str):
    """Invariants every report must satisfy."""
    report = analyze(raw)
    assert report.verdict in VERDICTS
    assert 0 <= report.probability <= 1 and report.risk_score == round(100 * report.probability)
    assert set(report.engine_scores) == set(ENGINES) and all(0 <= s <= 1 for s in report.engine_scores.values())
    assert all(f.engine in ENGINES for f in report.findings)
    if report.a_label:
        assert report.a_label.isascii() and report.a_label == report.a_label.lower()
    json.dumps(report.to_dict(), ensure_ascii=True)
    shown = render(report)          # the text report must never carry a live bidi / invisible character
    assert not any(is_bidi_control(ch) for ch in shown)
    assert all(ch == "\ufe0f" for ch in shown if is_default_ignorable(ch))   # only the warning icon's VS16
    return report


# --- Unicode fuzzing ----------------------------------------------------------

@given(st.text(max_size=80))
def test_any_text_gives_a_consistent_report(raw):
    check(raw)


@given(DOMAINS)
def test_domain_shaped_fuzz(domain):
    check(domain)


@given(DOMAINS, st.sampled_from(["http", "https", "HTTPS", "ftp", "ws"]), URL_PARTS, URL_PARTS, st.booleans())
def test_url_fuzz_finds_the_host(domain, scheme, userinfo, path, with_port):
    userinfo = userinfo.replace("/", "").replace("?", "").replace("#", "")
    url = f"{scheme}://{userinfo + '@' if userinfo else ''}{domain}{':8443' if with_port else ''}/{path}"
    report = check(url)
    assume("@" not in domain)
    expected = "".join(ch.lower() if ch.isascii() else ch for ch in unicodedata.normalize("NFC", domain))
    assert prepare(url).host == expected.rstrip(".") and report.input_type == "url"


@given(st.text(st.sampled_from(string.ascii_lowercase + string.digits + "-"), max_size=20))
def test_malformed_punycode_is_reported_not_crashed(tail):
    report = check(f"xn--{tail}.com")
    if not report.a_label:
        assert any(f.kind.startswith("idna_") for f in report.findings)


# --- metamorphic properties: an attack transformation must never come out SAFE --

@given(st.sampled_from(OFFICIAL), st.data())
def test_cyrillic_or_greek_letter_swap_is_always_caught(domain, data):
    rd, label = registrable(domain)
    positions = [i for i, ch in enumerate(label) if ch in LOOKALIKE]
    assume(positions)
    i = data.draw(st.sampled_from(positions))
    fake = label[:i] + data.draw(st.sampled_from(LOOKALIKE[label[i]])) + label[i + 1:]
    report = check(domain.replace(label, fake, 1))
    assert report.verdict == "MALICIOUS", [f.kind for f in report.findings]


@given(st.sampled_from(OFFICIAL), st.sampled_from(INVISIBLE), st.data())
def test_invisible_character_never_passes_as_safe(domain, invisible, data):
    i = data.draw(st.integers(0, len(domain)))
    report = check(domain[:i] + invisible + domain[i:])
    assert report.verdict != "SAFE" and "default_ignorable" in {f.kind for f in report.findings}


@given(st.one_of(st.sampled_from(OFFICIAL), st.from_regex(r"[a-z0-9]{1,12}\.(com|vn|net)", fullmatch=True)),
       st.sampled_from(BIDI), st.data())
def test_bidi_control_is_always_malicious(domain, control, data):
    i = data.draw(st.integers(0, len(domain)))
    report = check(domain[:i] + control + domain[i:])
    assert report.verdict == "MALICIOUS" and "bidi_control" in {f.kind for f in report.findings}


@given(st.lists(st.text(st.sampled_from(VIETNAMESE), min_size=2, max_size=12), min_size=1, max_size=3))
def test_vietnamese_is_never_seen_as_mixed_script(words):
    _, results = run_engines(".".join(words) + ".vn")
    unicode = results["unicode"]
    assert unicode.score == 0, [(f.kind, f.message) for f in unicode.findings]
    assert unicode.facts["restriction_level"] in ("ASCII-Only", "Single Script")


# --- algebraic properties of the building blocks --------------------------------

@given(st.text(max_size=30))
def test_skeleton_ignores_canonical_equivalence(text):
    assert skeleton(unicodedata.normalize("NFC", text)) == skeleton(unicodedata.normalize("NFD", text))


ASCII_LABEL = st.text(st.sampled_from(sorted(DOMAIN_CHARS)), max_size=12)


@given(ASCII_LABEL, ASCII_LABEL)
def test_visual_similarity_is_a_bounded_symmetric_distance(a, b):
    forward, backward = visual_similarity(a, b), visual_similarity(b, a)
    assert forward.distance == backward.distance and 0 <= forward.score <= 1
    assert forward.distance <= max(len(a), len(b))
    assert visual_similarity(a, a) == (1.0, 0.0, [])


@given(ASCII_LABEL, ASCII_LABEL)
def test_edit_distance_properties(a, b):
    d = edit_distance(a, b)
    assert d == edit_distance(b, a) and (d == 0) == (a == b)
    assert abs(len(a) - len(b)) <= d <= max(len(a), len(b))


SCORES = st.fixed_dictionaries({name: st.floats(0, 1) for name in ENGINES})


@given(SCORES, st.sampled_from(sorted(ENGINES)), st.floats(0, 1))
def test_more_evidence_never_lowers_the_risk(scores, engine, extra):
    stronger = {**scores, engine: min(1.0, scores[engine] + extra)}
    assert probability(stronger) >= probability(scores)
