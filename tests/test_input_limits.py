import io
import json
import sys

import pytest

from homoglyph_detector import analyze
from homoglyph_detector import cli
from homoglyph_detector.analyzer import ENGINES
from homoglyph_detector.cli import main
from homoglyph_detector.context import MAX_INPUT_LENGTH, MAX_RAW_LENGTH
from homoglyph_detector.visual import can_score_visually, visual_similarity


FAKE = "payp" + chr(0x430) + "l.com"


@pytest.mark.parametrize("raw,verdict", [
    ("https://www.paypal.com/signin?returnUri=" + "x" * 560, "SAFE"),      # login link with a long return URL
    ("https://click.mail.example.com/?qs=" + "ab12" * 92, "SAFE"),          # mail tracking link
    (f"https://{FAKE}/" + "a" * 1980, "MALICIOUS"),                          # padding must not hide an attack
])
def test_a_long_url_is_scored_by_its_host(raw, verdict):
    """The limit bounds what the engines scan (host, userinfo, name), not the length of the whole URL."""
    report = analyze(raw)
    assert len(raw) > MAX_INPUT_LENGTH and report.parse_status == "ok" and report.verdict == verdict


@pytest.mark.parametrize("raw", [
    "x" * (MAX_INPUT_LENGTH + 1),                                            # a name
    "https://" + "a" * (MAX_INPUT_LENGTH + 1) + ".com/",                     # a host
    "https://" + "u" * (MAX_INPUT_LENGTH + 1) + "@example.org/",             # a URL userinfo
    "a" * (MAX_INPUT_LENGTH + 1) + "@example.org",                           # an email local part
    "https://example.org/" + "a" * MAX_RAW_LENGTH,                           # the whole input
])
def test_an_oversized_input_never_reaches_an_engine(raw, monkeypatch):
    def fail(*args):
        raise AssertionError("oversized inputs must not reach an engine")

    monkeypatch.setitem(ENGINES, "visual", fail)
    report = analyze(raw, base_rate=0.001)
    assert (report.parse_status, report.parse_reason, report.verdict) == ("unsupported", "too_long", "SUSPICIOUS")
    assert report.input == report.target == report.skeleton == ""
    assert report.risk_score == 0 and report.probability_at_base_rate is None


@pytest.mark.parametrize("raw", ["x" * MAX_INPUT_LENGTH, "https://example.org/" + "a" * (MAX_RAW_LENGTH - 20)])
def test_inputs_at_the_limits_are_scored(raw):
    assert analyze(raw).parse_status == "ok"


def test_cli_drains_an_oversized_line_and_keeps_following_lines(tmp_path, monkeypatch, capsys):
    class BoundedStdin(io.StringIO):
        def readline(self, size=-1):
            assert 0 < size <= MAX_RAW_LENGTH + 2
            return super().readline(size)

    oversized = "https://example.org/" + "a" * (MAX_RAW_LENGTH * 2)
    prefix = "https://example.org/"
    at_limit = prefix + "a" * (MAX_RAW_LENGTH - len(prefix))
    lines = "#" + "a" * (MAX_INPUT_LENGTH * 3) + "\r\n" + at_limit + "\r\n" + oversized + "\r\nhttps://example.org/"
    path = tmp_path / "inputs.txt"
    path.write_bytes(lines.encode("utf-8"))
    for source in (str(path), "-"):
        monkeypatch.setattr(sys, "stdin", BoundedStdin(lines))
        assert main(["--json", "-f", source]) == 1
        rows = json.loads(capsys.readouterr().out)
        assert [row["parse_status"] for row in rows] == ["ok", "unsupported", "ok"]
        assert rows[0]["input"] == at_limit and rows[2]["input"] == "https://example.org/"
        assert rows[1]["parse_reason"] == "too_long" and rows[1]["input"] == ""

    assert main([oversized, f"https://{FAKE}/"]) == 2
    shown = capsys.readouterr().out
    assert "unsupported (too_long)" in shown and oversized not in shown


def test_batch_input_limit_applies_to_arguments_and_file_together(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "MAX_BATCH_INPUTS", 2)
    path = tmp_path / "inputs.txt"
    path.write_text("xn--pypal-4ve.com\n", encoding="utf-8")
    args = ["--json", "-f", str(path), "example.org"]
    assert main(args) == 2
    assert len(json.loads(capsys.readouterr().out)) == 2
    assert main(args + ["paypal.com"]) == cli.DATA_ERROR
    captured = capsys.readouterr()
    assert captured.out == "" and "batch exceeds 2 inputs" in captured.err


@pytest.mark.parametrize("prefix", ["", "#", " "])
def test_batch_character_limit_counts_drained_and_skipped_lines(monkeypatch, capsys, prefix):
    monkeypatch.setattr(cli, "MAX_BATCH_CHARACTERS", 2 * MAX_INPUT_LENGTH)
    monkeypatch.setattr(sys, "stdin", io.StringIO("example.org\n" + prefix + " " * (3 * MAX_INPUT_LENGTH)))
    assert main(["-f", "-"]) == cli.DATA_ERROR
    captured = capsys.readouterr()
    assert captured.out == "" and "batch exceeds" in captured.err


def test_batch_accepts_the_exact_character_limit(monkeypatch, capsys):
    text = "# comment\nexample.org\n"
    monkeypatch.setattr(cli, "MAX_BATCH_CHARACTERS", len(text) + len("apple.com"))
    monkeypatch.setattr(sys, "stdin", io.StringIO(text))
    assert main(["--json", "-f", "-", "apple.com"]) == 0
    assert [row["input"] for row in json.loads(capsys.readouterr().out)] == ["apple.com", "example.org"]


@pytest.mark.parametrize("raw,status,reason", [
    ("https://example.com:" + "9" * 4301 + "/", "rejected", "invalid_port"),   # past int()'s 4300-digit limit
    ("https://example.com:" + "0" * 4301 + "80/", "ok", ""),                  # leading zeros: still port 80
    ("https://example.com:1000000/", "rejected", "invalid_port"),
    ("https://example.com:65535/", "ok", ""),
    ("https://xn--zva847l.com/", "rejected", "invalid_joiner"),               # U+0378 (unassigned) + ZWJ
])
def test_hostile_url_parts_give_a_report_not_an_exception(raw, status, reason):
    report = analyze(raw)
    assert (report.parse_status, report.parse_reason) == (status, reason)
    assert report.to_integration_dict()["port"] == (80 if "080" in raw else 65535 if "65535" in raw else None)


def test_cli_refuses_a_file_that_is_not_utf8(tmp_path, capsys):
    path = tmp_path / "inputs.txt"
    path.write_bytes(b"paypal.com\n\xff\n")
    assert main(["--json", "-f", str(path)]) == cli.DATA_ERROR
    captured = capsys.readouterr()
    assert captured.out == "" and "data error" in captured.err and "Traceback" not in captured.err


@pytest.mark.parametrize("text,keyword", [
    ("rnicrosoft", "microsoft"),
    ("5hopee", "shopee"),
    ("vvhatsapp", "whatsapp"),
    ("gm\u0103\u012fl", "gmail"),
    ("paypa", "paypal"),
    ("x" * MAX_INPUT_LENGTH, "paypal"),
])
def test_visual_candidate_preserves_matches_below_one_edit(text, keyword):
    assert can_score_visually(text, keyword) == (visual_similarity(text, keyword).distance < 1)
