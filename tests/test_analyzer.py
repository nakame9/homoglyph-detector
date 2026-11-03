import codecs
import json
from pathlib import Path

import pytest

from homoglyph_detector import analyze, script_of, skeleton
from homoglyph_detector.analyzer import registrable
from homoglyph_detector.unicode_data import (confusable_type, is_bidi_control, is_default_ignorable,
                                             restriction_level)
from homoglyph_detector.cli import main

APPLE_CYRILLIC = "\u0430\u0440\u0440\u04cf\u0435"  # аррӏе — every letter is Cyrillic
APPLE_PUNYCODE = "xn--" + codecs.encode(APPLE_CYRILLIC, "punycode").decode()


def kinds(report):
    return {f.kind for f in report.findings}


@pytest.mark.parametrize("raw", [
    "p\u0430ypal.com",                 # one Cyrillic 'а'
    APPLE_CYRILLIC + ".com",           # whole-script confusable
    APPLE_PUNYCODE + ".com",           # same, as the browser/DNS sees it
    "user@p\u0430ypal.com",            # email
    "https://\u0430pple.com/login",    # URL
    "p\u0430ypal.github.io",          # homograph site on a hosting platform (PSL private suffix)
])
def test_malicious(raw):   # each has Unicode evidence, not only visual similarity
    assert analyze(raw).verdict == "MALICIOUS"


@pytest.mark.parametrize("raw, kind", [
    ("paypal-login.com", "brand_in_host"),
    ("gooogle.com", "brand_typosquat"),
    ("ex\u0430mple.com", "mixed_script"),
    ("paypal.net", "brand_unofficial"),
    ("\uff50\uff41\uff59\uff50\uff41\uff4c.com", "idna_mapped"),  # fullwidth: browsers resolve the real paypal.com
])
def test_flagged(raw, kind):
    report = analyze(raw)
    assert report.verdict != "SAFE"
    assert kind in kinds(report)


@pytest.mark.parametrize("raw", [
    "paypal.com", "www.paypal.com", "vietcombank.com.vn", "google.com.vn", "example.com",
    "ti\u1ebfngvi\u1ec7t.vn",          # tiếngviệt.vn — Vietnamese diacritics are not homoglyphs
    "\u0441\u0430\u0439\u0442.\u0440\u0444",  # сайт.рф — legit all-Cyrillic domain
    "Nguy\u1ec5n V\u0103n A",          # Vietnamese name
    "\u6771\u4eac\u3068\u3046\u304d\u3087.jp",  # Han + Hiragana is normal Japanese
])
def test_safe(raw):
    report = analyze(raw)
    assert report.verdict == "SAFE", report.findings
    assert "mixed_script" not in kinds(report)


def test_reports_the_fake_character():
    finding = next(f for f in analyze("p\u0430ypal.com").findings if f.kind == "confusable_char")
    assert finding.detail == {"position": 1, "char": "\u0430", "codepoint": "U+0430",
                              "script": "Cyrillic", "looks_like": "a"}


def test_name_homograph():
    assert analyze("G\u043e\u043egle support").verdict == "MALICIOUS"  # Cyrillic о's


def test_unicode_data():
    assert script_of("a") == "Latin" and script_of("\u0430") == "Cyrillic" and script_of("1") == "Common"
    assert skeleton("p\u0430ypal") == skeleton("paypal") == skeleton("paypa1")


def test_cli_exit_codes():
    assert main(["example.com"]) == 0
    assert main(["paypal-login.com"]) == 1   # combosquat alone: SUSPICIOUS
    assert main(["example.com", "p\u0430ypal.com"]) == 2


def test_cli_text_output_shows_hidden_characters(capsys):
    main(["invoice\u202efdp.exe"])
    out = capsys.readouterr().out
    assert "invoice<U+202E>fdp.exe" in out and "\u202e" not in out


def test_cli_shows_a_label(capsys):
    main([APPLE_CYRILLIC + ".com"])
    assert f"a-label : {APPLE_PUNYCODE}.com" in capsys.readouterr().out


def test_cli_json_output(capsys):
    main(["p\u0430ypal.com", "--json"])
    [report] = json.loads(capsys.readouterr().out)
    assert report["verdict"] == "MALICIOUS" and report["skeleton"] == skeleton("paypal.com")


# --- UTS #39 building blocks -------------------------------------------------

@pytest.mark.parametrize("text, level", [
    ("paypal", "ASCII-Only"),
    ("\u0441\u0430\u0439\u0442", "Single Script"),                 # сайт
    ("\u6771\u4eac\u3068\u3046\u304d\u3087", "Single Script"),     # 東京とうきょう (Japanese)
    ("abc\u3068\u3046\u304d\u3087", "Highly Restrictive"),         # Latin + Hiragana
    ("abc\u0644\u0639\u0631\u0628\u064a\u0629", "Moderately Restrictive"),  # Latin + Arabic
    ("p\u0430ypal", "Minimally Restrictive"),                     # Latin + Cyrillic
    ("pay\u200bpal", "Unrestricted"),                              # zero-width space
])
def test_restriction_level(text, level):
    assert restriction_level(text) == level


@pytest.mark.parametrize("x, y, kind", [
    ("rnicrosoft", "microsoft", "single-script"),
    ("p\u0430ypal", "paypal", "mixed-script"),
    (APPLE_CYRILLIC, "apple", "whole-script"),
    ("paypal", "paypal", None),
    ("abc", "xyz", None),
])
def test_confusable_type(x, y, kind):
    assert confusable_type(x, y) == kind


def test_report_carries_uts39_details():
    report = analyze(APPLE_PUNYCODE + ".com")
    assert report.restriction_level == "Single Script"
    brand = next(f for f in report.findings if f.kind == "brand_homograph")
    assert brand.detail["confusable_type"] == "whole-script"
    assert analyze("p\u0430ypal.com").restriction_level == "Minimally Restrictive"


def test_default_ignorable_is_stripped_and_flagged():
    report = analyze("pay\u200bpal.com")
    # UTS #46 drops the zero-width space, so this resolves to the real paypal.com: obfuscated, not fake.
    assert report.verdict != "SAFE" and report.a_label == "paypal.com"
    assert {"default_ignorable", "idna_mapped"} <= kinds(report)


@pytest.mark.parametrize("raw", [
    "\u202emoc.lapyap",          # RLO: displays as paypal.com
    "invoice\u202efdp.exe",      # RLO: displays as invoiceexe.pdf
    "user@\u2066paypal.com",     # isolate inside an address
])
def test_bidi_control(raw):
    report = analyze(raw)
    assert report.verdict == "MALICIOUS" and "bidi_control" in kinds(report)
    assert "default_ignorable" not in kinds(report)   # reported once, as the more specific kind


def test_repository_has_no_hidden_characters():
    """Dogfooding: no Trojan-Source-style bidi or invisible characters in our own files."""
    root = Path(__file__).resolve().parents[1]
    files = [p for p in root.rglob("*") if p.suffix in {".py", ".md", ".toml", ".yml", ".json"}
             and ".git" not in p.parts and "data" not in p.parts]
    assert len(files) > 5
    for path in files:
        for line_no, line in enumerate(path.read_text("utf-8").splitlines(), 1):
            hidden = [f"U+{ord(ch):04X}" for ch in line
                      if is_bidi_control(ch) or (is_default_ignorable(ch) and not 0xFE00 <= ord(ch) <= 0xFE0F)]
            assert not hidden, f"{path.relative_to(root)}:{line_no} contains {hidden}"


def test_mixed_numbers():
    assert "mixed_numbers" in kinds(analyze("ab1\u0663.com"))   # ASCII 1 + Arabic-Indic 3


def test_hidden_overlay():
    assert "hidden_overlay" in kinds(analyze("cafe\u0301\u0301.com"))  # same accent stacked twice


# --- IDNA2008 + Public Suffix List --------------------------------------------

@pytest.mark.parametrize("raw, kind", [
    ("abc\u05d0.com", "idna_bidi"),                    # Hebrew letter in a left-to-right label (RFC 5893)
    ("a\u200db.com", "idna_context"),                  # ZWJ outside its allowed context (RFC 5892 CONTEXTJ)
    ("xn--a.com", "idna_disallowed"),                  # punycode decodes, but to a control character
    ("xn--zz-.com", "idna_invalid"),                   # punycode decodes, but is not a valid A-label
    ("ab--c.com", "idna_invalid"),                     # hyphens in positions 3-4 are reserved
    ("x" * 64 + ".com", "idna_length"),                # label longer than 63 octets
    (".".join(["a" * 63] * 4) + ".com", "idna_length"),  # domain longer than 253 octets
])
def test_idna2008_rejects(raw, kind):
    # Evidence only: the benchmark gives the idna engine no weight, since an invalid domain cannot be visited.
    report = analyze(raw)
    assert kind in kinds(report) and report.a_label == "" and report.engine_scores["idna"] > 0


def test_a_label_u_label_conversion():
    assert analyze(APPLE_CYRILLIC + ".com").a_label == APPLE_PUNYCODE + ".com"
    report = analyze(APPLE_PUNYCODE.upper() + ".COM")
    assert report.target == APPLE_CYRILLIC + ".com" and report.a_label == APPLE_PUNYCODE + ".com"


def test_ascii_case_is_not_a_finding():
    report = analyze("PayPal.COM")
    assert report.verdict == "SAFE" and kinds(report) == {"allowlisted"}


def test_not_nfc_input_is_normalised_not_rejected():
    report = analyze("e\u0301x.com")   # e + combining acute accent
    assert "not_nfc" in kinds(report) and report.a_label == "xn--x-9fa.com" and report.verdict == "SAFE"


def test_round_trip_mismatch_is_reported(monkeypatch):
    import idna
    real_decode = idna.decode
    monkeypatch.setattr(idna, "decode", lambda text: real_decode(text) + "x")   # a lossy decoder
    assert "idna_roundtrip" in kinds(analyze("paypal.com"))


@pytest.mark.parametrize("host, expected", [
    ("login.paypal.com", ("paypal.com", "paypal")),
    ("www.vietcombank.com.vn", ("vietcombank.com.vn", "vietcombank")),
    ("www.google.co.uk", ("google.co.uk", "google")),
    ("paypal.github.io", ("paypal.github.io", "paypal")),   # private suffix: every site is separate
    ("\u0441\u0430\u0439\u0442.\u0440\u0444", ("\u0441\u0430\u0439\u0442.\u0440\u0444", "\u0441\u0430\u0439\u0442")),
])
def test_public_suffix_list(host, expected):
    assert registrable(host) == expected


# --- evidence classes and the visual-only rule ---------------------------------------

@pytest.mark.parametrize("raw", [
    "rnicrosoft.com",                  # 'rn' -> 'm': in confusables.txt, but ASCII and font-dependent
    "g00gle.com",                      # '0' -> 'o'
    "paypa1.com",                      # '1' -> 'l'
    "vietcornbank.com.vn",             # Vietnamese bank, multi-level TLD
])
@pytest.mark.parametrize("policy", ["default", "banking", "browser"])
def test_ascii_lookalikes_are_flagged_but_never_malicious_alone(raw, policy):
    report = analyze(raw, policy=policy)
    assert report.verdict == "SUSPICIOUS" and "visual similarity" in report.verdict_note
    assert report.evidence["brand_basis"] == "visual" and "unicode_confusable" not in report.evidence


@pytest.mark.parametrize("raw, basis", [
    ("p\u0430ypal.com", "unicode"),    # other-script letter
    ("\u0251pple.com", "unicode"),     # Latin-extended letter listed in confusables.txt
    ("paypak.com", "spelling"),        # one edit, not a look-alike
    ("paypal-login.com", "name"),      # the literal brand name on an unofficial domain
])
def test_independent_brand_evidence_can_be_malicious(raw, basis):
    report = analyze(raw, policy="banking")
    assert report.verdict == "MALICIOUS" and report.verdict_note == ""
    assert basis in report.evidence["brand_basis"].split(",")


def test_every_finding_has_an_evidence_class():
    classes = {"unicode_confusable", "visual_similarity", "brand_impersonation", "protocol"}
    for raw in ("p\u0430ypal.com", "5hopee.vn", "paypal-login.com", "xn--a.com", "pay\u200bpal.com", "G\u043e\u043egle x"):
        assert all(f.evidence in classes for f in analyze(raw).findings)
    report = analyze("5hopee.vn")
    assert report.evidence == {"visual_similarity": "high", "brand_impersonation": "medium", "brand_basis": "visual"}
