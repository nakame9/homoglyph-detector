import codecs
import json

import pytest

from homoglyph_detector import analyze, script_of, skeleton
from homoglyph_detector.unicode_data import confusable_type, restriction_level
from homoglyph_detector.cli import main

APPLE_CYRILLIC = "аррӏе"  # аррӏе — every letter is Cyrillic
APPLE_PUNYCODE = "xn--" + codecs.encode(APPLE_CYRILLIC, "punycode").decode()


def kinds(report):
    return {f.kind for f in report.findings}


@pytest.mark.parametrize("raw", [
    "pаypal.com",                 # one Cyrillic 'а'
    APPLE_CYRILLIC + ".com",           # whole-script confusable
    APPLE_PUNYCODE + ".com",           # same, as the browser/DNS sees it
    "rnicrosoft.com",                  # 'rn' -> 'm', pure ASCII
    "g00gle.com",                      # '0' -> 'o'
    "paypa1.com",                      # '1' -> 'l'
    "vietcornbank.com.vn",             # Vietnamese bank, multi-level TLD
    "user@pаypal.com",            # email
    "https://аpple.com/login",    # URL
    "ｐａｙｐａｌ.com",  # fullwidth ｐａｙｐａｌ
])
def test_malicious(raw):
    assert analyze(raw).verdict == "MALICIOUS"


@pytest.mark.parametrize("raw, kind", [
    ("paypal-login.com", "brand_in_host"),
    ("gooogle.com", "brand_typosquat"),
    ("exаmple.com", "mixed_script"),
    ("paypal.net", "brand_unofficial"),
    ("xn--a.com", "punycode"),         # decodes to nothing
    ("xn--zz-.com", "punycode"),       # decodes to plain ASCII: not a real IDN
])
def test_suspicious(raw, kind):
    report = analyze(raw)
    assert report.verdict == "SUSPICIOUS"
    assert kind in kinds(report)


@pytest.mark.parametrize("raw", [
    "paypal.com", "www.paypal.com", "vietcombank.com.vn", "google.com.vn", "example.com",
    "tiếngviệt.vn",          # tiếngviệt.vn — Vietnamese diacritics are not homoglyphs
    "сайт.рф",  # сайт.рф — legit all-Cyrillic domain
    "Nguyễn Văn A",          # Vietnamese name
    "東京とうきょ.jp",  # Han + Hiragana is normal Japanese
])
def test_safe(raw):
    report = analyze(raw)
    assert report.verdict == "SAFE", report.findings
    assert "mixed_script" not in kinds(report)


def test_reports_the_fake_character():
    finding = next(f for f in analyze("pаypal.com").findings if f.kind == "confusable_char")
    assert finding.detail == {"position": 1, "char": "а", "codepoint": "U+0430",
                              "script": "Cyrillic", "looks_like": "a"}


def test_name_homograph():
    assert analyze("Gооgle support").verdict == "MALICIOUS"  # Cyrillic о's


def test_unicode_data():
    assert script_of("a") == "Latin" and script_of("а") == "Cyrillic" and script_of("1") == "Common"
    assert skeleton("pаypal") == skeleton("paypal") == skeleton("paypa1")


def test_cli_exit_codes():
    assert main(["example.com"]) == 0
    assert main(["gooogle.com"]) == 1
    assert main(["example.com", "pаypal.com"]) == 2


def test_cli_json_output(capsys):
    main(["pаypal.com", "--json"])
    [report] = json.loads(capsys.readouterr().out)
    assert report["verdict"] == "MALICIOUS" and report["skeleton"] == skeleton("paypal.com")


# --- UTS #39 building blocks -------------------------------------------------

@pytest.mark.parametrize("text, level", [
    ("paypal", "ASCII-Only"),
    ("сайт", "Single Script"),                 # сайт
    ("東京とうきょ", "Single Script"),     # 東京とうきょう (Japanese)
    ("abcとうきょ", "Highly Restrictive"),         # Latin + Hiragana
    ("abcلعربية", "Moderately Restrictive"),  # Latin + Arabic
    ("pаypal", "Minimally Restrictive"),                     # Latin + Cyrillic
    ("pay​pal", "Unrestricted"),                              # zero-width space
])
def test_restriction_level(text, level):
    assert restriction_level(text) == level


@pytest.mark.parametrize("x, y, kind", [
    ("rnicrosoft", "microsoft", "single-script"),
    ("pаypal", "paypal", "mixed-script"),
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
    assert analyze("pаypal.com").restriction_level == "Minimally Restrictive"


def test_invisible_character_is_stripped_and_flagged():
    report = analyze("pay​pal.com")
    assert report.verdict == "MALICIOUS" and "invisible_char" in kinds(report)


def test_mixed_numbers():
    assert "mixed_numbers" in kinds(analyze("ab1٣.com"))   # ASCII 1 + Arabic-Indic 3


def test_hidden_overlay():
    assert "hidden_overlay" in kinds(analyze("café́.com"))  # same accent stacked twice
