"""URL targets are read the way browsers read them (WHATWG URL Standard): roadmap 0.13.1, task A1.

P1   a URL a browser rejects is not scored: parse_status 'rejected', sent for review as SUSPICIOUS (exit 1),
     never SAFE, and a syntax error never raises the verdict.
P1-b a bidi formatting control in the host of a rejected URL is still evidence: it is scored from that
     evidence alone, against the thresholds of the policy in use.
P3   an IP host skips the IDN engines: canonical form -> ip_host (info); IPv4 in an unusual form -> SUSPICIOUS.
"""
import json
import re
import unicodedata
from pathlib import Path
from urllib.parse import quote

import pytest

from homoglyph_detector import analyze
from homoglyph_detector.cli import main
from homoglyph_detector.context import prepare
from homoglyph_detector.scoring import custom_profile, profile
from homoglyph_detector.unicode_data import script_of

FAKE = "payp\u0430l.com"          # Cyrillic '\u0430'
BIDI_FORMATTING = [*range(0x202A, 0x202F), *range(0x2066, 0x206A)]   # embedding, override, isolate


def kinds(report) -> set[str]:
    return {f.kind for f in report.findings}


@pytest.mark.parametrize("url", [f"https:///{FAKE}/", f"https:/{FAKE}/", f"https:{FAKE}/", f"https:\\\\{FAKE}/",
                                 f"{FAKE}/?q=https://x.org/", f"ht\ttps://{FAKE}/"])
def test_the_host_is_found_however_many_slashes(url):
    report = analyze(url)
    assert report.parse_status == "ok" and report.a_label == "xn--paypl-7ve.com", (report.input_type, report.target)
    assert report.verdict == "MALICIOUS"


@pytest.mark.parametrize("url", ["https://paypal.com/", "https://paypal.com/login?next=https://x.org/",
                                 "https://paypal.com:443/", "https://paypal.com:/", "file:///etc/paypal"])
def test_benign_urls_stay_safe(url):
    report = analyze(url)
    assert report.parse_status == "ok" and report.verdict == "SAFE", sorted(kinds(report))


REJECTED = {
    "https://paypal.com%40evil.com/": "forbidden_code_point",
    "https://paypal.com%3A443/": "forbidden_code_point",     # was SAFE and allowlisted as paypal.com
    "https://pay\uff20pal.com/": "forbidden_code_point",     # fullwidth @ maps to @
    "https://a\u2100b.com/": "forbidden_code_point",         # \u2100 maps to 'a/c'
    "https://example.org:65536/": "invalid_port",
    "https://g00gle.com:abc/": "invalid_port",               # was MALICIOUS through an IDNA error
    "https://256.1.1.1/": "invalid_ipv4",
    "https://example.123/": "invalid_ipv4",
    "https://[paypal.com/": "invalid_ipv6",
    "https://[::1/": "invalid_ipv6",
    "https://a\u200cb.com/": "invalid_joiner",
    "https://\u200eapple.com/": "disallowed_code_point",     # LRM is not a P1-b character
    "http://": "empty",
    "https:///": "empty",
}


@pytest.mark.parametrize("url,reason", REJECTED.items())
def test_a_url_browsers_reject_is_sent_for_review_not_scored(url, reason):
    report = analyze(url)
    assert (report.parse_status, report.parse_reason) == ("rejected", reason)
    assert report.verdict == "SUSPICIOUS" and report.probability == 0 and report.risk_score == 0
    assert "url_rejected" in kinds(report)


@pytest.mark.parametrize("raw", ["", "   ", ".", "@"])
def test_empty_input_is_rejected(raw):
    report = analyze(raw)
    assert (report.parse_status, report.parse_reason, report.verdict) == ("rejected", "empty", "SUSPICIOUS")


@pytest.mark.parametrize("raw", ["Nguyễn Văn A", "PayPal Support", "paypal.com", "user@paypal.com"])
def test_ordinary_inputs_are_not_rejected(raw):
    assert analyze(raw).parse_status == "ok"


# --- P3: IP hosts ------------------------------------------------------------------

@pytest.mark.parametrize("url,ip", [("https://192.168.1.1/", "192.168.1.1"), ("http://192.168.0.1/login", "192.168.0.1"),
                                    ("https://[::1]/", "::1"), ("https://[::1]:8080/", "::1")])
def test_a_canonical_ip_host_is_reported_not_flagged(url, ip):
    report = analyze(url)
    assert prepare(url).ip == ip and report.parse_status == "ok"
    assert report.verdict == "SAFE" and "ip_host" in kinds(report) and "ip_obfuscated" not in kinds(report)


@pytest.mark.parametrize("url", ["https://0x7f.1/", "https://2130706433/", "https://0177.0.0.1/", "https://127.1/",
                                 "https://0x7F000001/"])
def test_an_ipv4_written_to_hide_it_is_suspicious(url):
    report = analyze(url)
    assert prepare(url).ip == "127.0.0.1" and report.parse_status == "ok"
    assert report.verdict == "SUSPICIOUS" and "ip_obfuscated" in kinds(report)


def test_userinfo_brand_before_an_ip_host_is_still_caught():
    assert analyze("https://paypal.com@192.168.1.1/").verdict != "SAFE"


# --- P1-b: bidi formatting controls in a rejected host -----------------------------

@pytest.mark.parametrize("name", ["default", "banking", "browser"])
@pytest.mark.parametrize("encoded", [False, True], ids=["direct", "percent"])
@pytest.mark.parametrize("codepoint", BIDI_FORMATTING, ids=lambda c: f"U+{c:04X}")
def test_bidi_formatting_control_in_a_rejected_host_stays_malicious(codepoint, encoded, name):
    control = quote(chr(codepoint)) if encoded else chr(codepoint)
    report = analyze(f"https://{control}apple.com/", policy=name)
    assert report.parse_status == "rejected" and report.verdict == "MALICIOUS"
    assert "bidi_control" in kinds(report) and report.engine_scores["brand"] == 0


def test_p1b_follows_the_thresholds_of_a_custom_policy():
    url = "https://\u202eapple.com/"
    assert analyze(url, policy=custom_profile(0.05, 0.0005)).verdict == analyze(url, policy="browser").verdict
    strict = {"name": "never malicious", "suspicious": 0.5, "malicious": 1.0}
    report = analyze(url, policy=strict)       # p = 0.999992 shows as 1.0 but stays below the threshold 1
    assert report.verdict == "SUSPICIOUS" and report.parse_status == "rejected"


@pytest.mark.parametrize("url", ["https://apple.com/\u202e", "https://apple.com/?q=\u2067x"])
def test_bidi_outside_the_host_follows_the_normal_policy(url):
    assert analyze(url).parse_status == "ok"


# --- CLI: exit codes and base rate -------------------------------------------------

@pytest.mark.parametrize("inputs,code", [
    (["https://paypal.com/"], 0),
    (["https://paypal.com/", "https://g00gle.com:abc/"], 1),                 # needs review
    (["https://g00gle.com:abc/", f"https://{FAKE}/"], 2),                    # MALICIOUS wins over review
    (["https://\u202eapple.com/"], 2),
])
def test_exit_code_of_a_batch(inputs, code, capsys):
    assert main(inputs) == code


@pytest.mark.parametrize("url", ["https://\u202eapple.com/", "https://g00gle.com:abc/"])
def test_base_rate_is_not_applied_to_an_unscored_url(url, capsys):
    plain = main(["--json", url])
    capsys.readouterr()
    assert main(["--json", "--base-rate", "0.001", url]) == plain
    row = json.loads(capsys.readouterr().out)[0]
    assert "probability_at_base_rate" in row and row["probability_at_base_rate"] is None
    assert main(["--base-rate", "0.001", url]) == plain     # the text report prints, no TypeError
    assert "rejected" in capsys.readouterr().out


def test_base_rate_still_applies_to_a_scored_url(capsys):
    main(["--json", "--base-rate", "0.001", f"https://{FAKE}/"])
    assert json.loads(capsys.readouterr().out)[0]["probability_at_base_rate"] is not None


def test_builtin_thresholds_are_below_the_p1b_probability():
    """P1-b keeps line 65 of the golden corpus MALICIOUS under every built-in profile only because of this."""
    assert all(profile(name)["malicious"] < 0.99999 for name in ("default", "banking", "browser"))


# --- differential test against the WHATWG reference data ------------------------------

WPT = [json.loads(line) for line in (Path(__file__).resolve().parent / "golden" / "wpt_url_hosts.jsonl")
       .read_text("utf-8").splitlines()]
IPV4 = re.compile(r"[0-9]+(\.[0-9]+){3}")


@pytest.mark.parametrize("case", WPT, ids=lambda case: case["input"].encode("unicode_escape").decode()[:60])
def test_host_parsing_agrees_with_the_url_standard(case):
    """web-platform-tests url/resources/urltestdata.json at commit bff876f9648b29675a01b47fade4ee5431da5726:
    the absolute http(s)/ws(s)/ftp URLs whose result does not depend on a base URL (418 cases)."""
    ctx = prepare(case["input"])
    assert (ctx.parse_status == "rejected") == case["failure"], ctx.parse_reason
    hostname = case.get("hostname", "")
    if hostname.startswith("[") or IPV4.fullmatch(hostname):
        assert ctx.ip == hostname.strip("[]")
    elif not case["failure"]:   # the destination a browser visits, also where strict IDNA2008 has no form for it
        assert (ctx.a_label or ctx.browser_host) == hostname.rstrip("."), (ctx.a_label, ctx.browser_host)


@pytest.mark.parametrize("url,host", [("https://example_.com/", "example_.com"), ("https://☃.com/", "xn--n3h.com")])
def test_a_browser_destination_survives_a_strict_idna_error(url, host):
    report = analyze(url)
    row = report.to_integration_dict()
    assert report.parse_status == "ok" and (row["host"], row["input"]) == (host, f"https://{host}")


@pytest.mark.parametrize("url", ["git://%70aypal.com/", "ssh://git@github.com/x", "foo://PAYPAL.com/"])
def test_an_opaque_host_is_not_scored(url):
    """Non-special schemes keep the host as written (no percent-decoding, case or IDNA): never allowlisted."""
    report = analyze(url)
    assert (report.parse_status, report.parse_reason, report.verdict) == ("unsupported", "opaque_host", "SUSPICIOUS")
    assert {f.kind for f in report.findings} == {"input_unsupported"} and report.to_integration_dict()["host"] is None
    assert "paypal.com" not in report.target


NEWER = next((chr(c) for c in range(0x80, 0x30000) if unicodedata.category(chr(c)) == "Cn"
              and script_of(chr(c)) not in ("Unknown", "Common", "Inherited")), None)


@pytest.mark.skipif(NEWER is None, reason="this Python's Unicode database is as new as the bundled tables")
@pytest.mark.parametrize("shape", ["https://{}x.com/", "{}x.com", "user@{}x.com"])
def test_a_character_newer_than_the_runtime_is_unsupported_not_invalid(shape):
    report = analyze(shape.format(NEWER))
    assert (report.parse_status, report.parse_reason) == ("unsupported", "unicode_newer_than_runtime")
    assert report.verdict == "SUSPICIOUS" and "url_rejected" not in {f.kind for f in report.findings}


# --- a domain or email host with a control character --------------------------------

CONTROLS = [chr(0x1b) + "[2J", chr(0x00), chr(0x07), chr(0x7f), chr(0x9b) + "31m", chr(0x85)]


@pytest.mark.parametrize("control", CONTROLS, ids=lambda c: f"U+{ord(c[0]):04X}")
@pytest.mark.parametrize("shape", ["evil{}.com", "pay{}pal.com", "user@pay{}pal.com", "pay{}pal.com/login"])
def test_a_host_with_a_control_character_is_never_safe(shape, control):
    """No browser or resolver accepts a control character in a host: like a rejected URL, send it for review."""
    report = analyze(shape.format(control))
    assert (report.parse_status, report.parse_reason) == ("rejected", "forbidden_code_point")
    assert report.verdict == "SUSPICIOUS"


@pytest.mark.parametrize("raw", [chr(0x1b) + "[1mPayPal Support", "us" + chr(0x1b) + "er@paypal.com"])
def test_a_control_character_outside_a_host_is_left_to_the_display(raw):
    """Names and email local parts are shown escaped (A3); only a host decides where mail or a link goes."""
    assert analyze(raw).parse_status == "ok"
