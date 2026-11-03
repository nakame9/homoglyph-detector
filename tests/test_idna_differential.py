"""Differential testing between IDNA implementations.

    legacy  IDNA2003: Python's built-in 'idna' codec, used by socket / urllib and older clients
    modern  IDNA2008 + UTS #46 (non-transitional): the `idna` package, like current browsers

Where both resolve a host but to different domains, one string reaches two sites depending on the
software, which an attacker can exploit. Hypothesis checks that every such difference has a known
cause, and that the idna engine reports each one.
"""
import stringprep
import unicodedata

import idna
import pytest
from hypothesis import given
from hypothesis import strategies as st

from homoglyph_detector import analyze
from homoglyph_detector.context import prepare
from homoglyph_detector.engines.idna_engine import legacy_a_label

DEVIATIONS = {chr(0x00DF), chr(0x03C2), chr(0x200C), chr(0x200D)}   # UTS #46 deviation characters


def modern(host: str) -> str | None:
    try:
        return idna.encode(host, uts46=True).decode("ascii")
    except idna.IDNAError:
        return None


def cause(ch: str) -> str | None:
    """Why IDNA2003 and UTS #46 can treat this character differently, or None."""
    if ch in DEVIATIONS:
        return "deviation character"
    if unicodedata.ucd_3_2_0.category(ch) == "Cn":
        return "not in Unicode 3.2"
    try:
        now = idna.uts46_remap(ch, std3_rules=False, transitional=False)
    except idna.IDNAError:
        return "refused by UTS #46"
    then = unicodedata.ucd_3_2_0.normalize("NFKC", stringprep.map_table_b2(ch))
    return "mapping changed since Unicode 3.2" if then != now else None


# Documented behaviour of both implementations (a library update that changes any of these is noticed).
KNOWN = [
    # input,                         IDNA2003 (legacy),   UTS #46 (modern)
    ("fa\u00df.de",                  "fass.de",           "xn--fa-hia.de"),     # sharp s: deviation
    ("\u03c3\u03bf\u03c6\u03bf\u03c2.gr", "xn--0xaakcn.gr", "xn--0xaajbq.gr"),  # final sigma: deviation
    ("a\u200db.com",                 "ab.com",            None),                # ZWJ dropped vs refused
    ("i\u2764.ws",                   "xn--i-7iq.ws",      None),                # symbol: allowed only in 2003
    ("ti\u1ebfngvi\u1ec7t.vn",       "xn--tingvit-5t4cyc.vn", "xn--tingvit-5t4cyc.vn"),   # agree
    ("\u0441\u0430\u0439\u0442.\u0440\u0444", "xn--80aswg.xn--p1ai", "xn--80aswg.xn--p1ai"),  # agree
]


@pytest.mark.parametrize("host, legacy, expected_modern", KNOWN)
def test_documented_differences(host, legacy, expected_modern):
    assert legacy_a_label(host) == legacy
    assert modern(host) == expected_modern
    reported = "idna_differential" in {f.kind for f in analyze(host).findings}
    assert reported == (legacy != expected_modern)


LABEL_CHARS = st.one_of(
    st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789-"),
    st.characters(min_codepoint=0x00A0, max_codepoint=0x024F),   # Latin-1, Latin Extended
    st.characters(min_codepoint=0x0370, max_codepoint=0x04FF),   # Greek, Cyrillic
    st.characters(min_codepoint=0x1E00, max_codepoint=0x1FFF),   # Latin / Greek Extended
    st.characters(min_codepoint=0x2000, max_codepoint=0x2BFF),   # punctuation, symbols, letterlike
    st.characters(min_codepoint=0xFF00, max_codepoint=0xFFEF),   # fullwidth forms
    st.characters(min_codepoint=0xA640, max_codepoint=0xA7FF),   # newer Cyrillic / Latin letters
    st.sampled_from(sorted(DEVIATIONS)),
)


@given(st.text(LABEL_CHARS, min_size=1, max_size=8))
def test_every_disagreement_has_a_known_cause(label):
    host = label + ".com"
    legacy, now = legacy_a_label(host), modern(host)
    if legacy and now and legacy != now:
        assert {cause(ch) for ch in label} - {None}, (label, legacy, now)


@given(st.text(LABEL_CHARS, min_size=1, max_size=8))
def test_engine_reports_every_disagreement(label):
    ctx = prepare(label + ".com")
    if not ctx.host or ctx.host.isascii():
        return
    legacy = legacy_a_label(ctx.host)
    disagree = legacy is not None and legacy != (ctx.a_label or None)
    assert ("idna_differential" in {f.kind for f in analyze(label + ".com").findings}) == disagree


def test_legacy_codec_for_post_unicode_3_2_letters_depends_on_the_python_build():
    """'\u023a' (added after Unicode 3.2): CPython's stringprep lowercases it with the running
    Python's tables in some patch releases (3.10.20, 3.12.3 -> same as browsers) and not in others
    (3.11.18, 3.13.18 -> a different domain). So never pin the legacy result for such characters;
    the engine reports whatever the Python it runs on would resolve."""
    host = "\u023a.com"
    legacy = legacy_a_label(host)
    assert legacy in ("xn--wma.com", "xn--cgj.com") and modern(host) == "xn--cgj.com"
    assert ("idna_differential" in {f.kind for f in analyze(host).findings}) == (legacy != "xn--cgj.com")
